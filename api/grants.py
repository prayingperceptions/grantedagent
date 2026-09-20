"""Grant and match endpoints.

Two different scopes live in this module, and keeping them straight is the
whole job:

* ``grants`` is the **shared catalogue**. Every federal, national and state
  grant is the same row for every customer, so it is not tenant-scoped - but it
  is still authentication-gated, because the catalogue is the product.

* ``matches`` is **per-tenant**. A match is one nonprofit's scored opinion about
  one grant. Every read and every write is filtered by the caller's membership,
  and a match belonging to another tenant is reported as 404 rather than 403 so
  match IDs cannot be probed.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from api.deps import ROLE_MEMBER, CurrentUser, Tenant
from hunter.db import get_db
from hunter.models import (
    MATCH_STATUSES,
    STATUS_APPROVED,
    STATUS_REJECTED,
    Grant,
    HunterRun,
    Match,
    _utcnow,
)
from tracking import service as tracking

router = APIRouter(prefix="/api", tags=["grants"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class GrantOut(BaseModel):
    id: int
    external_id: str | None = None
    title: str
    agency: str | None = None
    deadline: date | None = None
    amount_min: float | None = None
    amount_max: float | None = None
    description: str | None = None
    url: str | None = None
    source: str
    state_code: str | None = None

    model_config = {"from_attributes": True}


class MatchOut(BaseModel):
    id: int
    grant: GrantOut
    score: float
    status: str
    rationale: dict[str, Any] | None = None
    similarity: float | None = None
    state_boost: float | None = None
    excluded: bool = False

    model_config = {"from_attributes": True}


class GrantListOut(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[GrantOut]


class MatchListOut(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[MatchOut]


class ReviewIn(BaseModel):
    status: str = Field(description=f"one of {', '.join(MATCH_STATUSES)}")
    note: str | None = Field(default=None, max_length=5000)


class RunOut(BaseModel):
    id: int
    started_at: Any
    finished_at: Any | None = None
    federal_found: int
    foundation_found: int
    state_total: int
    state_breakdown: dict[str, Any] | None = None
    errors: dict[str, Any] | None = None

    model_config = {"from_attributes": True}


class StatsOut(BaseModel):
    grants_total: int
    by_source: dict[str, int]
    by_state: dict[str, int]
    upcoming_deadlines: int
    matches_by_status: dict[str, int]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _match_for_scope(db: Session, match_id: int, scope: Tenant) -> Match:
    """Load a match belonging to the caller's tenant, or raise 404.

    Filtering in the query rather than fetching and then comparing keeps the
    ownership check in the same statement as the read, so no window exists in
    which an unscoped ``Match`` object is reachable by the handler.
    """
    match = (
        db.execute(
            select(Match)
            .options(joinedload(Match.grant))
            .where(Match.id == match_id, Match.nonprofit_id == scope.nonprofit_id)
        )
        .unique()
        .scalar_one_or_none()
    )
    if match is None:
        # Identical response whether the match does not exist or belongs to
        # someone else; that distinction is the leak.
        raise HTTPException(status_code=404, detail="Resource not found.")
    return match


# ---------------------------------------------------------------------------
# Catalogue (shared across tenants, authentication required)
# ---------------------------------------------------------------------------


@router.get("/grants", response_model=GrantListOut)
def list_grants(
    principal: CurrentUser,
    db: Session = Depends(get_db),
    source: str | None = Query(None, description="federal, national_foundation, state_CA …"),
    state_code: str | None = Query(None, min_length=2, max_length=2),
    q: str | None = Query(None, max_length=200, description="substring match on title"),
    deadline_before: date | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> GrantListOut:
    stmt = select(Grant)
    count_stmt = select(func.count()).select_from(Grant)

    if source:
        stmt = stmt.where(Grant.source == source)
        count_stmt = count_stmt.where(Grant.source == source)
    if state_code:
        stmt = stmt.where(Grant.state_code == state_code.upper())
        count_stmt = count_stmt.where(Grant.state_code == state_code.upper())
    if q:
        pattern = f"%{q}%"
        stmt = stmt.where(Grant.title.ilike(pattern))
        count_stmt = count_stmt.where(Grant.title.ilike(pattern))
    if deadline_before:
        stmt = stmt.where(Grant.deadline.is_not(None), Grant.deadline <= deadline_before)
        count_stmt = count_stmt.where(
            Grant.deadline.is_not(None), Grant.deadline <= deadline_before
        )

    total = db.execute(count_stmt).scalar_one()
    rows = (
        db.execute(
            stmt.order_by(Grant.deadline.asc().nulls_last(), Grant.id.desc())
            .limit(limit)
            .offset(offset)
        )
        .scalars()
        .all()
    )

    tracking.record_usage(
        db,
        name=tracking.EVENT_GRANT_VIEWED,
        user_id=principal.user.id,
        properties={"count": len(rows), "source": source, "state_code": state_code},
    )
    return GrantListOut(total=total, limit=limit, offset=offset, items=list(rows))


@router.get("/grants/{grant_id}", response_model=GrantOut)
def get_grant(
    grant_id: int, principal: CurrentUser, db: Session = Depends(get_db)
) -> Grant:
    grant = db.get(Grant, grant_id)
    if grant is None:
        raise HTTPException(status_code=404, detail="Resource not found.")
    return grant


# ---------------------------------------------------------------------------
# Matches: the human-in-the-loop inbox (strictly tenant-scoped)
# ---------------------------------------------------------------------------


@router.get("/nonprofits/{nonprofit_id}/matches", response_model=MatchListOut)
def list_matches(
    nonprofit_id: int,
    scope: Tenant,
    db: Session = Depends(get_db),
    status: str | None = Query(None, description=f"one of {', '.join(MATCH_STATUSES)}"),
    min_score: float = Query(0.0, ge=-100.0, le=100.0),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> MatchListOut:
    """The tenant's ranked shortlist.

    ``nonprofit_id`` comes from the path and is resolved to a membership by the
    ``Tenant`` dependency before this body runs.
    """
    conditions = [
        Match.nonprofit_id == scope.nonprofit_id,
        ~Match.excluded,
        Match.score >= min_score,
    ]
    if status:
        if status not in MATCH_STATUSES:
            raise HTTPException(
                status_code=422, detail=f"status must be one of {MATCH_STATUSES}"
            )
        conditions.append(Match.status == status)

    total = db.execute(
        select(func.count()).select_from(Match).where(*conditions)
    ).scalar_one()
    rows = (
        db.execute(
            select(Match)
            .options(joinedload(Match.grant))
            .where(*conditions)
            .order_by(Match.score.desc(), Match.id.desc())
            .limit(limit)
            .offset(offset)
        )
        .unique()
        .scalars()
        .all()
    )

    tracking.record_usage(
        db,
        name=tracking.EVENT_MATCH_VIEWED,
        nonprofit_id=scope.nonprofit_id,
        user_id=scope.user_id,
        properties={"count": len(rows), "status": status},
    )
    return MatchListOut(total=total, limit=limit, offset=offset, items=list(rows))


@router.get("/nonprofits/{nonprofit_id}/matches/{match_id}", response_model=MatchOut)
def get_match(
    nonprofit_id: int,
    match_id: int,
    scope: Tenant,
    db: Session = Depends(get_db),
) -> Match:
    return _match_for_scope(db, match_id, scope)


@router.patch("/nonprofits/{nonprofit_id}/matches/{match_id}", response_model=MatchOut)
def review_match(
    nonprofit_id: int,
    match_id: int,
    payload: ReviewIn,
    scope: Tenant,
    db: Session = Depends(get_db),
) -> Match:
    """Record a human decision. The only path that changes match status."""
    # A viewer is read-only. Without this check any member of the organization,
    # including someone given view access to a report, could approve or reject a
    # grant on the organization's behalf.
    if not scope.has_role(ROLE_MEMBER):
        raise HTTPException(
            status_code=403, detail=f"Requires the {ROLE_MEMBER} role."
        )

    if payload.status not in MATCH_STATUSES:
        raise HTTPException(
            status_code=422, detail=f"status must be one of {MATCH_STATUSES}"
        )

    match = _match_for_scope(db, match_id, scope)
    match.status = payload.status
    match.review_note = payload.note
    # The reviewer is the authenticated user, never a client-supplied string -
    # otherwise the audit trail records whoever the caller names.
    match.reviewed_by = scope.user.email
    match.reviewed_at = _utcnow()
    db.flush()

    tracking.record_usage(
        db,
        name=tracking.EVENT_MATCH_REVIEWED,
        nonprofit_id=scope.nonprofit_id,
        user_id=scope.user_id,
        properties={"match_id": match.id, "status": payload.status},
    )
    tracking.record_audit(
        db,
        action="match.reviewed",
        nonprofit_id=scope.nonprofit_id,
        actor_user_id=scope.user_id,
        actor_email=scope.user.email,
        target_type="match",
        target_id=match.id,
        detail=f"status={payload.status}",
    )
    return match


@router.post(
    "/nonprofits/{nonprofit_id}/matches/{match_id}/approve", response_model=MatchOut
)
def approve_match(
    nonprofit_id: int,
    match_id: int,
    scope: Tenant,
    note: str | None = Query(None, max_length=5000),
    db: Session = Depends(get_db),
) -> Match:
    return review_match(
        nonprofit_id, match_id, ReviewIn(status=STATUS_APPROVED, note=note), scope, db
    )


@router.post(
    "/nonprofits/{nonprofit_id}/matches/{match_id}/reject", response_model=MatchOut
)
def reject_match(
    nonprofit_id: int,
    match_id: int,
    scope: Tenant,
    note: str | None = Query(None, max_length=5000),
    db: Session = Depends(get_db),
) -> Match:
    return review_match(
        nonprofit_id, match_id, ReviewIn(status=STATUS_REJECTED, note=note), scope, db
    )


# ---------------------------------------------------------------------------
# Ops
# ---------------------------------------------------------------------------


@router.get("/runs", response_model=list[RunOut])
def list_runs(
    principal: CurrentUser,
    db: Session = Depends(get_db),
    limit: int = Query(20, ge=1, le=100),
) -> list[HunterRun]:
    """Hunter run history.

    A run sweeps every source for the whole deployment, so a run row is
    operational rather than tenant data. Restricted to staff.
    """
    if not principal.user.is_staff:
        raise HTTPException(status_code=403, detail="Staff access required.")
    return list(
        db.execute(
            select(HunterRun).order_by(HunterRun.started_at.desc()).limit(limit)
        ).scalars()
    )


@router.get("/nonprofits/{nonprofit_id}/stats", response_model=StatsOut)
def stats(
    nonprofit_id: int,
    scope: Tenant,
    db: Session = Depends(get_db),
) -> StatsOut:
    """Catalogue size plus *this tenant's* match counts.

    The catalogue numbers are global and safe to share. The match breakdown is
    filtered by ``scope.nonprofit_id``; an unscoped count would disclose how
    many grants a competitor had reviewed.
    """
    grants_total = db.execute(select(func.count()).select_from(Grant)).scalar_one()

    by_source = {
        src: count
        for src, count in db.execute(
            select(Grant.source, func.count()).group_by(Grant.source)
        ).all()
    }
    by_state = {
        (state or "unscoped"): count
        for state, count in db.execute(
            select(Grant.state_code, func.count()).group_by(Grant.state_code)
        ).all()
    }
    upcoming = db.execute(
        select(func.count()).select_from(Grant).where(Grant.deadline >= date.today())
    ).scalar_one()

    # Pre-seed every status so the dashboard renders zeroes rather than gaps.
    by_status = {match_status: 0 for match_status in MATCH_STATUSES}
    for match_status, count in db.execute(
        select(Match.status, func.count())
        .where(Match.nonprofit_id == scope.nonprofit_id)
        .group_by(Match.status)
    ).all():
        by_status[match_status] = count

    return StatsOut(
        grants_total=grants_total,
        by_source=by_source,
        by_state=by_state,
        upcoming_deadlines=upcoming,
        matches_by_status=by_status,
    )


__all__ = ["router"]