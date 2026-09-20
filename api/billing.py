"""Billing routes: checkout, portal, plan status, and the Stripe webhook.

The webhook route is the only endpoint in the application that is both
unauthenticated and state-changing. It is safe because the handler refuses to
act on a payload whose signature does not verify against the endpoint secret -
so the "caller" is provably Stripe, not an anonymous client.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api import ratelimit
from api.deps import Tenant
from billing import stripe_service
from billing.models import STATUS_NONE, Subscription
from billing.plans import PLANS, get_plan
from hunter.config import get_settings
from hunter.db import get_db
from tracking import service as tracking

logger = logging.getLogger("api.billing")

router = APIRouter(prefix="/api/billing", tags=["billing"])


class PlanOut(BaseModel):
    key: str
    name: str
    price_usd_year: int
    max_nonprofits: int
    max_members_per_nonprofit: int
    hunts_per_day: int
    drafts_per_month: int
    custom_sources: bool
    team_seats: bool
    support_tier: str


class SubscriptionOut(BaseModel):
    plan: PlanOut
    status: str
    current_period_end: str | None = None
    cancel_at_period_end: bool = False
    billing_configured: bool
    stripe_publishable_key: str | None = None
    is_paid: bool


class CheckoutIn(BaseModel):
    plan_key: str = Field(max_length=32)
    success_url: str | None = Field(default=None, max_length=2000)
    cancel_url: str | None = Field(default=None, max_length=2000)


class PortalIn(BaseModel):
    return_url: str | None = Field(default=None, max_length=2000)


class UrlOut(BaseModel):
    url: str


def _plan_out(plan) -> PlanOut:
    return PlanOut(
        key=plan.key,
        name=plan.name,
        price_usd_year=plan.price_usd_year,
        max_nonprofits=plan.max_nonprofits,
        max_members_per_nonprofit=plan.max_members_per_nonprofit,
        hunts_per_day=plan.hunts_per_day,
        drafts_per_month=plan.drafts_per_month,
        custom_sources=plan.custom_sources,
        team_seats=plan.team_seats,
        support_tier=plan.support_tier,
    )


@router.get("/plans", response_model=list[PlanOut])
def list_plans() -> list[PlanOut]:
    """The public plan catalogue. No authentication needed."""
    return [_plan_out(plan) for plan in PLANS.values()]


@router.get("/{nonprofit_id}/subscription", response_model=SubscriptionOut)
def get_subscription(
    nonprofit_id: int,
    scope: Tenant,
    db: Annotated[Session, Depends(get_db)],
) -> SubscriptionOut:
    """Current plan and period for a tenant. Scoped to the caller's membership."""
    settings = get_settings()
    plan_key = stripe_service.current_plan_key(db, scope.nonprofit_id)
    plan = get_plan(plan_key)

    customer = stripe_service.get_customer(db, scope.nonprofit_id)
    latest: Subscription | None = None
    if customer is not None:
        latest = db.query(Subscription).filter(
            Subscription.customer_id == customer.id
        ).order_by(Subscription.updated_at.desc()).first()

    return SubscriptionOut(
        plan=_plan_out(plan),
        status=latest.status if latest else STATUS_NONE,
        current_period_end=(
            latest.current_period_end.isoformat()
            if latest and latest.current_period_end
            else None
        ),
        cancel_at_period_end=bool(latest.cancel_at_period_end) if latest else False,
        billing_configured=settings.billing_configured,
        stripe_publishable_key=settings.stripe_publishable_key or None,
        is_paid=plan.is_paid,
    )


@router.post("/{nonprofit_id}/checkout", response_model=UrlOut)
def start_checkout(
    nonprofit_id: int,
    payload: CheckoutIn,
    request: Request,
    scope: Tenant,
    db: Annotated[Session, Depends(get_db)],
) -> UrlOut:
    """Begin a Stripe Checkout session. Requires the owner role.

    Only an owner may change the payment relationship, because it commits the
    organization to a charge.
    """
    if not scope.has_role("owner"):
        raise HTTPException(status_code=403, detail="Requires the owner role.")

    settings = get_settings()
    if payload.plan_key not in PLANS:
        raise HTTPException(status_code=422, detail="Unknown plan.")
    if not settings.billing_configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing is not configured on this deployment.",
        )

    base = settings.frontend_base_url.rstrip("/")
    success = payload.success_url or f"{base}/billing?checkout=success"
    cancel = payload.cancel_url or f"{base}/billing?checkout=cancelled"

    try:
        url = stripe_service.create_checkout_session(
            db,
            nonprofit=scope.nonprofit,
            plan_key=payload.plan_key,
            success_url=success,
            cancel_url=cancel,
            email=scope.user.email,
        )
    except stripe_service.BillingNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except stripe_service.BillingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    tracking.record_audit(
        db,
        action="billing.checkout_started",
        nonprofit_id=scope.nonprofit_id,
        actor_user_id=scope.user_id,
        actor_email=scope.user.email,
        target_type="plan",
        target_id=payload.plan_key,
        ip=ratelimit.client_ip(request),
    )
    tracking.record_usage(
        db,
        name=tracking.EVENT_CHECKOUT_STARTED,
        nonprofit_id=scope.nonprofit_id,
        user_id=scope.user_id,
        properties={"plan_key": payload.plan_key},
    )
    return UrlOut(url=url)


@router.post("/{nonprofit_id}/portal", response_model=UrlOut)
def open_portal(
    nonprofit_id: int,
    payload: PortalIn,
    scope: Tenant,
    db: Annotated[Session, Depends(get_db)],
) -> UrlOut:
    """Open the Stripe Billing Portal so the owner can manage the card."""
    if not scope.has_role("owner"):
        raise HTTPException(status_code=403, detail="Requires the owner role.")

    settings = get_settings()
    return_url = payload.return_url or f"{settings.frontend_base_url.rstrip('/')}/billing"
    try:
        url = stripe_service.create_portal_session(
            db, nonprofit=scope.nonprofit, return_url=return_url
        )
    except stripe_service.BillingNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except stripe_service.BillingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return UrlOut(url=url)


# --------------------------------------------------------------------------
# Webhook
# --------------------------------------------------------------------------

webhook_router = APIRouter(prefix="/api/stripe", tags=["billing"])


@webhook_router.post("/webhook")
async def stripe_webhook(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, Any]:
    """Receive Stripe events.

    Reads the **raw body** because signature verification is over bytes; parsing
    to JSON first would re-encode and break the digest. No authentication
    dependency is applied - the signature is the authentication.
    """
    payload = await request.body()
    signature = request.headers.get("stripe-signature")

    try:
        event = stripe_service.verify_webhook(payload, signature)
    except stripe_service.BillingNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except stripe_service.BillingError as exc:
        # 400 tells Stripe the delivery failed and it will retry with backoff.
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        outcome = stripe_service.apply_event(db, event)
    except Exception:
        logger.exception("webhook processing error")
        raise HTTPException(status_code=500, detail="Webhook processing failed.")

    return {"received": True, "outcome": outcome}


__all__ = ["router", "webhook_router"]