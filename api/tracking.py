"""Tenant activity and audit endpoints.

Both are scoped through :class:`TenantScope`, so a member of one nonprofit
cannot read another's activity by changing an id - the scope dependency
resolves the membership before the handler runs.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import ROLE_ADMIN, Tenant
from billing import entitlements
from hunter.db import get_db
from tracking import service as tracking

router = APIRouter(prefix="/api/nonprofits", tags=["tracking"])


class UsageEventOut(BaseModel):
    id: int
    name: str
    quantity: int
    user_id: int | None = None
    properties: dict[str, Any] | None = None
    created_at: str


class AuditEventOut(BaseModel):
    id: int
    action: str
    outcome: str
    actor_user_id: int | None = None
    actor_email: str | None = None
    target_type: str | None = None
    target_id: str | None = None
    detail: str | None = None
    created_at: str


class UsageSummaryOut(BaseModel):
    totals: dict[str, int]
    plan_key: str
    hunts_today: dict[str, Any]
    drafts_this_month: dict[str, Any]


@router.get("/{nonprofit_id}/activity", response_model=list[UsageEventOut])
def list_activity(
    nonprofit_id: int,
    scope: Tenant,
    db: Annotated[Session, Depends(get_db)],
    limit: int = Query(50, ge=1, le=500),
) -> list[UsageEventOut]:
    """Recent usage events for the tenant.

    ``properties`` is already scrubbed at write time, so there is no risk of a
    secret surfacing here even if a caller recorded one by mistake.
    """
    return [
        UsageEventOut(
            id=event.id,
            name=event.name,
            quantity=event.quantity,
            user_id=event.user_id,
            properties=event.properties,
            created_at=event.created_at.isoformat() if event.created_at else "",
        )
        for event in tracking.recent_events(db, nonprofit_id=scope.nonprofit_id, limit=limit)
    ]


@router.get("/{nonprofit_id}/audit", response_model=list[AuditEventOut])
def list_audit(
    nonprofit_id: int,
    scope: Tenant,
    db: Annotated[Session, Depends(get_db)],
    limit: int = Query(50, ge=1, le=500),
) -> list[AuditEventOut]:
    """The tenant's audit trail.

    Restricted to admins: the trail names who did what, which is management
    information rather than something every member needs.
    """

    if not scope.has_role(ROLE_ADMIN):
        raise HTTPException(status_code=403, detail=f"Requires the {ROLE_ADMIN} role.")

    return [
        AuditEventOut(
            id=event.id,
            action=event.action,
            outcome=event.outcome,
            actor_user_id=event.actor_user_id,
            actor_email=event.actor_email,
            target_type=event.target_type,
            target_id=event.target_id,
            detail=event.detail,
            created_at=event.created_at.isoformat() if event.created_at else "",
        )
        for event in tracking.recent_audit(db, nonprofit_id=scope.nonprofit_id, limit=limit)
    ]


@router.get("/{nonprofit_id}/usage", response_model=UsageSummaryOut)
def usage_summary(
    nonprofit_id: int,
    scope: Tenant,
    db: Annotated[Session, Depends(get_db)],
) -> UsageSummaryOut:
    """Usage against entitlements, for the dashboard quota widget."""
    plan = entitlements.plan_for(db, scope.nonprofit_id)
    hunts = entitlements.check_hunts(db, nonprofit_id=scope.nonprofit_id, plan=plan)
    drafts = entitlements.check_drafts(db, nonprofit_id=scope.nonprofit_id, plan=plan)
    return UsageSummaryOut(
        totals=tracking.usage_totals(db, nonprofit_id=scope.nonprofit_id),
        plan_key=plan.key,
        hunts_today={
            "used": hunts.used,
            "limit": hunts.limit,
            "remaining": hunts.remaining,
        },
        drafts_this_month={
            "used": drafts.used,
            "limit": drafts.limit,
            "remaining": drafts.remaining,
        },
    )


__all__ = ["router"]