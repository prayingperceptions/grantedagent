"""Plan entitlements: the checks that make a plan mean something.

Every limit is read from the tenant's current plan, and usage is read from the
tracking tables scoped to that tenant. Both inputs come from the server, never
from the request, so a client cannot claim headroom it does not have.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from accounts.models import Membership
from billing import stripe_service
from billing.plans import Entitlement, Plan, check, get_plan
from tracking.service import count_usage_since


class EntitlementError(Exception):
    """Raised when a tenant has exhausted an entitlement."""

    def __init__(self, entitlement: Entitlement) -> None:
        self.entitlement = entitlement
        super().__init__(entitlement.reason or "Limit reached.")


def plan_for(db: Session, nonprofit_id: int) -> Plan:
    """The plan currently governing a tenant."""
    return get_plan(stripe_service.current_plan_key(db, nonprofit_id))


def _start_of_month(now: datetime | None = None) -> datetime:
    now = now or datetime.now(UTC)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _start_of_day(now: datetime | None = None) -> datetime:
    now = now or datetime.now(UTC)
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


def member_count(db: Session, nonprofit_id: int) -> int:
    return int(
        db.scalar(
            select(func.count())
            .select_from(Membership)
            .where(Membership.nonprofit_id == nonprofit_id)
        )
        or 0
    )


def nonprofit_count(db: Session, user_id: int) -> int:
    """How many tenants this user belongs to."""
    return int(
        db.scalar(
            select(func.count())
            .select_from(Membership)
            .where(Membership.user_id == user_id)
        )
        or 0
    )


# -- individual entitlements ------------------------------------------------


def check_members(scope_plan: Plan, used: int) -> Entitlement:
    return check(used, scope_plan.max_members_per_nonprofit, label="team member", plan=scope_plan)


def check_hunts(db: Session, *, nonprofit_id: int, plan: Plan) -> Entitlement:
    used = count_usage_since(
        db,
        nonprofit_id=nonprofit_id,
        name="hunter.run",
        since=_start_of_day(),
    )
    return check(used, plan.hunts_per_day, label="daily hunter run", plan=plan)


def check_drafts(db: Session, *, nonprofit_id: int, plan: Plan) -> Entitlement:
    used = count_usage_since(
        db,
        nonprofit_id=nonprofit_id,
        name="drafts.generated",
        since=_start_of_month(),
    )
    return check(used, plan.drafts_per_month, label="monthly draft", plan=plan)


def require_team_seats(plan: Plan) -> None:
    """Raise when the plan does not include inviting teammates at all."""
    if not plan.team_seats:
        raise EntitlementError(
            Entitlement(
                allowed=False,
                limit=0,
                used=0,
                reason=(
                    f"Team members are not included on the {plan.name} plan. "
                    "Upgrade to invite colleagues."
                ),
            )
        )


def require_custom_sources(plan: Plan) -> None:
    if not plan.custom_sources:
        raise EntitlementError(
            Entitlement(
                allowed=False,
                limit=0,
                used=0,
                reason=(
                    f"Custom grant sources are not included on the {plan.name} "
                    "plan."
                ),
            )
        )


__all__ = [
    "EntitlementError",
    "check_drafts",
    "check_hunts",
    "check_members",
    "member_count",
    "nonprofit_count",
    "plan_for",
    "require_custom_sources",
    "require_team_seats",
]