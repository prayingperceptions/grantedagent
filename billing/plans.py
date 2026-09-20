"""Plan definitions and entitlements.

The plans here are the source of truth for what a tenant may do. Stripe holds
the *payment* state; this module holds the *product* rules. Keeping them apart
means a Stripe misconfiguration cannot silently grant unlimited usage, and a
plan can be changed here without touching billing code.

Prices are displayed on the marketing site and passed to Stripe as price IDs at
checkout time, but no code trusts a price sent by the client - the plan is
looked up server-side from a Stripe price ID that we configured.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

# Stripe subscription statuses that grant paid access. ``past_due`` is included
# on purpose: a card that fails on renewal should not instantly lock a
# nonprofit out of an active grant deadline. Stripe's own dunning retries for
# weeks; when it gives up the status becomes ``canceled`` or ``unpaid``.
ACTIVE_STRIPE_STATUSES: Final = frozenset({"active", "trialing", "past_due"})


@dataclass(frozen=True)
class Plan:
    """What a plan permits."""

    key: str
    name: str
    price_usd_year: int
    # Maximum number of nonprofits (tenants) the account may create.
    max_nonprofits: int
    # Maximum members per nonprofit.
    max_members_per_nonprofit: int
    # Hunter runs per day (each run sweeps every configured source).
    hunts_per_day: int
    # Draft documents per month.
    drafts_per_month: int
    # Whether custom state source adapters are selectable.
    custom_sources: bool
    # Whether the tenant may invite members at all.
    team_seats: bool
    support_tier: str

    @property
    def is_paid(self) -> bool:
        return self.price_usd_year > 0


# Hard caps are integers, not ``None`` sentinels, so entitlement checks are a
# plain comparison with no "unlimited" special case to get wrong.
UNLIMITED: Final = 1_000_000

PLANS: Final[dict[str, Plan]] = {
    "community": Plan(
        key="community",
        name="Community",
        price_usd_year=0,
        max_nonprofits=1,
        max_members_per_nonprofit=1,
        hunts_per_day=2,
        drafts_per_month=10,
        custom_sources=False,
        team_seats=False,
        support_tier="community",
    ),
    "turnkey": Plan(
        key="turnkey",
        name="Turnkey",
        price_usd_year=948,
        max_nonprofits=1,
        max_members_per_nonprofit=5,
        hunts_per_day=24,
        drafts_per_month=100,
        custom_sources=False,
        team_seats=True,
        support_tier="email",
    ),
    "growth": Plan(
        key="growth",
        name="Growth",
        price_usd_year=1990,
        max_nonprofits=3,
        max_members_per_nonprofit=25,
        hunts_per_day=96,
        drafts_per_month=500,
        custom_sources=True,
        team_seats=True,
        support_tier="priority",
    ),
    "enterprise": Plan(
        key="enterprise",
        name="Enterprise",
        price_usd_year=4900,
        max_nonprofits=UNLIMITED,
        max_members_per_nonprofit=UNLIMITED,
        hunts_per_day=UNLIMITED,
        drafts_per_month=UNLIMITED,
        custom_sources=True,
        team_seats=True,
        support_tier="dedicated",
    ),
}

DEFAULT_PLAN: Final = "community"


def get_plan(key: str | None) -> Plan:
    """Look up a plan, falling back to the free tier.

    Falling back rather than raising is deliberate: an unknown or stale plan key
    on a subscription row must not crash a billing page. The safe default is
    the most restrictive plan.
    """
    return PLANS.get((key or "").strip().lower(), PLANS[DEFAULT_PLAN])


def plan_from_price_id(price_id: str | None, configured: dict[str, str]) -> str:
    """Map a Stripe price ID to a plan key using the configured mapping.

    The mapping comes from configuration, not from Stripe metadata, so a
    compromised Stripe account cannot relabel a $0 price as enterprise.
    """
    if not price_id:
        return DEFAULT_PLAN
    return configured.get(price_id.strip(), DEFAULT_PLAN)


@dataclass(frozen=True)
class Entitlement:
    allowed: bool
    limit: int
    used: int
    reason: str | None = None

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)


def check(used: int, limit: int, *, label: str, plan: Plan) -> Entitlement:
    """Compare usage against a limit, producing a user-facing reason."""
    if used >= limit:
        return Entitlement(
            allowed=False,
            limit=limit,
            used=used,
            reason=(
                f"You have reached your {label} limit ({limit}) on the "
                f"{plan.name} plan."
            ),
        )
    return Entitlement(allowed=True, limit=limit, used=used)


__all__ = [
    "ACTIVE_STRIPE_STATUSES",
    "DEFAULT_PLAN",
    "PLANS",
    "UNLIMITED",
    "Entitlement",
    "Plan",
    "check",
    "get_plan",
    "plan_from_price_id",
]