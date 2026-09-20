"""Soul vault and drafting endpoints.

Security posture:

* Every route is tenant-scoped. The soul belongs to one nonprofit, and the
  ``Tenant`` dependency proves membership before a handler runs. There is no
  route that lists every tenant's soul.
* Secrets inside a soul are **never returned**. ``SoulOut`` has no field for
  them - the values are not redacted at render time, they are never loaded into
  the response model at all.
* Drafts and matches are filtered by ``scope.nonprofit_id`` on every read, and
  a draft belonging to another tenant answers 404.
* Writes require the member role or above; a read-only viewer cannot replace
  the organization's soul or generate documents.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from api import ratelimit
from api.deps import ROLE_MEMBER, CurrentUser, Tenant
from billing import entitlements
from hunter.db import get_db
from hunter.models import Draft, Match, NonprofitModel
from inner_court import vault
from inner_court.loader import SoulInvalid
from inner_court.states import STATES_50
from scribe import draft_generator
from tracking import service as tracking

logger = logging.getLogger("api.inner_court")

router = APIRouter(prefix="/api", tags=["inner-court"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class LocationOut(BaseModel):
    city: str = ""
    state: str = ""
    zip: str = ""
    country: str = "US"


class NonprofitProfileOut(BaseModel):
    """The soul's view of the nonprofit. No database id, no secrets."""

    name: str = ""
    ein: str = ""
    mission: str = ""
    populations_served: list[str] = []
    focus_areas: list[str] = []
    past_grants: list[str] = []


class NonprofitOut(BaseModel):
    id: int
    slug: str
    name: str = ""
    state: str = ""
    city: str = ""
    soul_configured: bool = False
    soul_updated_at: Any | None = None


class SoulOut(BaseModel):
    location: LocationOut
    nonprofit: NonprofitProfileOut
    matching_rules: dict[str, Any]
    templates: dict[str, str]
    # Names only, so the UI can show *that* a key is set. Values are not loaded.
    secrets_configured: list[str] = []
    updated_at: Any | None = None


class SoulWriteIn(BaseModel):
    content: str = Field(max_length=200_000, description="raw soul.md YAML content")


class SoulValidateIn(BaseModel):
    content: str = Field(max_length=200_000, description="raw soul.md YAML content")


class SoulValidateOut(BaseModel):
    valid: bool
    errors: list[str] = []
    warnings: list[str] = []


class DraftGenerateIn(BaseModel):
    match_id: int
    kinds: list[str] = Field(
        default_factory=lambda: list(draft_generator.DEFAULT_KINDS), max_length=20
    )


class DraftOut(BaseModel):
    id: int
    match_id: int
    kind: str
    title: str | None = None
    body: str
    source_url: str | None = None
    status: str
    missing_inputs: list[str] | None = None
    template_used: str | None = None

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_write(scope: Tenant) -> None:
    """Viewers may read a soul; only members and above may change anything."""
    if not scope.has_role(ROLE_MEMBER):
        raise HTTPException(
            status_code=403, detail=f"Requires the {ROLE_MEMBER} role."
        )


def _soul_out(soul, nonprofit: NonprofitModel) -> SoulOut:
    return SoulOut(
        location=LocationOut(
            city=soul.nonprofit.city,
            state=soul.nonprofit.state,
            zip=soul.nonprofit.zip,
            country=soul.nonprofit.country,
        ),
        nonprofit=NonprofitProfileOut(
            name=soul.nonprofit.name,
            ein=soul.nonprofit.ein,
            mission=soul.nonprofit.mission,
            populations_served=list(soul.nonprofit.populations_served),
            focus_areas=list(soul.nonprofit.focus_areas),
            past_grants=list(soul.nonprofit.past_grants),
        ),
        matching_rules={
            "states": list(soul.matching_rules.states),
            "exclusions": list(soul.matching_rules.exclusions),
            "min_amount": soul.matching_rules.min_amount,
            "focus_areas": list(soul.matching_rules.focus_areas),
        },
        templates=dict(soul.templates),
        # `soul.secrets` holds values; only the keys are exposed.
        secrets_configured=sorted(soul.secrets),
        updated_at=nonprofit.soul_updated_at,
    )


def _match_for_scope(db: Session, match_id: int, scope: Tenant) -> Match:
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
        raise HTTPException(status_code=404, detail="Resource not found.")
    return match


# ---------------------------------------------------------------------------
# Soul
# ---------------------------------------------------------------------------


@router.get("/nonprofits/{nonprofit_id}/soul", response_model=SoulOut)
def get_soul(nonprofit_id: int, scope: Tenant, db: Session = Depends(get_db)) -> SoulOut:
    """The tenant's soul profile, decrypted for the owner of the vault."""
    if not scope.nonprofit.soul_encrypted:
        raise HTTPException(
            status_code=404,
            detail="No soul is configured for this organization yet.",
        )
    try:
        soul = vault.load_soul_for(db, scope.nonprofit)
    except vault.VaultUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        # Wrong key or tampered blob. The message is deliberately generic; the
        # specific failure is in the server log.
        logger.error("soul load failed nonprofit_id=%s", scope.nonprofit_id)
        raise HTTPException(
            status_code=500, detail="The soul vault could not be opened."
        ) from exc

    if soul is None:
        raise HTTPException(status_code=404, detail="No soul is configured.")
    return _soul_out(soul, scope.nonprofit)


@router.put("/nonprofits/{nonprofit_id}/soul", response_model=SoulOut)
def put_soul(
    nonprofit_id: int,
    payload: SoulWriteIn,
    request: Request,
    scope: Tenant,
    db: Annotated[Session, Depends(get_db)],
) -> SoulOut:
    """Create or replace this tenant's soul.

    The content is validated, then encrypted, then stored. Nothing is written
    if parsing fails, so a tenant cannot end up with an unusable soul.
    """
    _require_write(scope)
    try:
        soul = vault.save_soul(db, scope.nonprofit, payload.content)
    except SoulInvalid as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except vault.VaultUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    tracking.record_usage(
        db,
        name=tracking.EVENT_SOUL_UPDATED,
        nonprofit_id=scope.nonprofit_id,
        user_id=scope.user_id,
    )
    tracking.record_audit(
        db,
        action="soul.updated",
        nonprofit_id=scope.nonprofit_id,
        actor_user_id=scope.user_id,
        actor_email=scope.user.email,
        target_type="nonprofit",
        target_id=scope.nonprofit_id,
        ip=ratelimit.client_ip(request),
    )
    return _soul_out(soul, scope.nonprofit)


@router.post("/soul/validate", response_model=SoulValidateOut)
def validate_soul(payload: SoulValidateIn, principal: CurrentUser) -> SoulValidateOut:
    """Dry-run soul content before saving.

    Authenticated but not tenant-scoped: it parses text the caller supplied and
    reads no stored data, so there is nothing to scope it to.
    """
    from inner_court.loader import parse_soul

    errors: list[str] = []
    warnings: list[str] = []

    try:
        soul = parse_soul(payload.content)
    except SoulInvalid as exc:
        return SoulValidateOut(valid=False, errors=[str(exc)])

    if soul.nonprofit.state and soul.nonprofit.state not in STATES_50:
        warnings.append(f"state {soul.nonprofit.state} is not one of the 50 US states")
    if not soul.nonprofit.mission.strip():
        warnings.append("nonprofit.mission is empty; semantic matching will be weak")
    empty = [k for k, v in soul.templates.items() if not str(v).strip()]
    if empty:
        warnings.append(
            f"templates {', '.join(sorted(empty))} are empty; drafts will ask for human input"
        )
    if not soul.matching_rules.states:
        warnings.append(
            "matching_rules.states is empty; no grants will receive a location boost"
        )

    return SoulValidateOut(valid=True, errors=errors, warnings=warnings)


@router.delete("/nonprofits/{nonprofit_id}/soul", status_code=204)
def delete_soul(
    nonprofit_id: int,
    request: Request,
    scope: Tenant,
    db: Annotated[Session, Depends(get_db)],
) -> None:
    """Delete the tenant's stored soul. Requires admin."""
    from api.deps import ROLE_ADMIN

    if not scope.has_role(ROLE_ADMIN):
        raise HTTPException(status_code=403, detail=f"Requires the {ROLE_ADMIN} role.")

    vault.clear_soul(db, scope.nonprofit)
    tracking.record_audit(
        db,
        action="soul.deleted",
        nonprofit_id=scope.nonprofit_id,
        actor_user_id=scope.user_id,
        actor_email=scope.user.email,
        target_type="nonprofit",
        target_id=scope.nonprofit_id,
        ip=ratelimit.client_ip(request),
    )


# ---------------------------------------------------------------------------
# Drafts
# ---------------------------------------------------------------------------


@router.post("/nonprofits/{nonprofit_id}/drafts/generate", response_model=list[DraftOut])
def generate_drafts(
    nonprofit_id: int,
    payload: DraftGenerateIn,
    request: Request,
    scope: Tenant,
    db: Annotated[Session, Depends(get_db)],
) -> list[Draft]:
    """Generate reviewable drafts for one of *this tenant's* matches.

    The match is resolved through the scope first, so passing another tenant's
    match id produces a 404 rather than a draft built from their grant list.
    """
    _require_write(scope)

    match = _match_for_scope(db, payload.match_id, scope)

    try:
        soul = vault.load_soul_for(db, scope.nonprofit)
    except vault.VaultUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if soul is None:
        raise HTTPException(
            status_code=422,
            detail="Configure a soul before generating drafts.",
        )

    # Drafts are metered monthly, so check the entitlement before generating.
    plan = entitlements.plan_for(db, scope.nonprofit_id)
    entitlement = entitlements.check_drafts(db, nonprofit_id=scope.nonprofit_id, plan=plan)
    if not entitlement.allowed:
        raise HTTPException(status_code=402, detail=entitlement.reason)

    try:
        drafts = draft_generator.generate_for_match(
            db, match, soul, kinds=payload.kinds
        )
    except draft_generator.DraftError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    tracking.record_usage(
        db,
        name=tracking.EVENT_DRAFT_GENERATED,
        nonprofit_id=scope.nonprofit_id,
        user_id=scope.user_id,
        quantity=max(1, len(drafts)),
        properties={"match_id": match.id, "kinds": payload.kinds},
    )
    tracking.record_audit(
        db,
        action="draft.generated",
        nonprofit_id=scope.nonprofit_id,
        actor_user_id=scope.user_id,
        actor_email=scope.user.email,
        target_type="match",
        target_id=match.id,
        detail=f"kinds={','.join(payload.kinds)}",
        ip=ratelimit.client_ip(request),
    )
    return drafts


@router.get("/nonprofits/{nonprofit_id}/drafts", response_model=list[DraftOut])
def list_drafts(
    nonprofit_id: int,
    scope: Tenant,
    db: Annotated[Session, Depends(get_db)],
    match_id: int | None = Query(None),
    status: str | None = Query(None, max_length=32),
    limit: int = Query(50, ge=1, le=200),
) -> list[Draft]:
    """Drafts for this tenant.

    ``Draft`` has no ``nonprofit_id`` column, so scoping goes through the
    ``matches`` join. Filtering on ``match_id`` alone would be an IDOR - the
    join to ``Match`` is what confines the result to this tenant.
    """
    stmt = (
        select(Draft)
        .join(Match, Match.id == Draft.match_id)
        .where(Match.nonprofit_id == scope.nonprofit_id)
    )
    if match_id is not None:
        stmt = stmt.where(Draft.match_id == match_id)
    if status:
        stmt = stmt.where(Draft.status == status)
    return list(db.execute(stmt.order_by(Draft.id.desc()).limit(limit)).scalars())


@router.get("/nonprofits/{nonprofit_id}/drafts/{draft_id}", response_model=DraftOut)
def get_draft(
    nonprofit_id: int,
    draft_id: int,
    scope: Tenant,
    db: Annotated[Session, Depends(get_db)],
) -> Draft:
    draft = (
        db.execute(
            select(Draft)
            .join(Match, Match.id == Draft.match_id)
            .where(Draft.id == draft_id, Match.nonprofit_id == scope.nonprofit_id)
        )
        .scalar_one_or_none()
    )
    if draft is None:
        raise HTTPException(status_code=404, detail="Resource not found.")
    return draft


__all__ = ["router"]