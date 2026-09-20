"""Stripe integration: checkout, portal, and webhook reconciliation.

Three things are load-bearing here, and each is a place where a naive
implementation leaks money or trust:

1. **Webhook signatures are verified before the body is trusted.** Anyone can
   POST to a public URL; only a payload signed with the endpoint secret proves
   it came from Stripe. Signature verification uses the raw request bytes, not
   a re-serialised dict - re-encoding JSON changes whitespace and invalidates
   the signature.

2. **Plan assignment comes from a configured price→plan map, not from the
   payload.** The webhook tells us *which price* is subscribed; which *plan*
   that price represents is our decision, read from configuration. A
   compromised or mis-set price cannot promote an account.

3. **Events are idempotent.** Stripe retries, and can deliver an event more
   than once. The unique index on the event ID makes a replay a no-op instead
   of a double-applied side effect.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

import stripe
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from billing.models import Customer, Subscription, WebhookEvent
from billing.plans import ACTIVE_STRIPE_STATUSES, DEFAULT_PLAN, plan_from_price_id
from hunter.config import get_settings
from hunter.models import NonprofitModel

logger = logging.getLogger("billing.stripe")


class BillingError(Exception):
    """Billing operation failed. Message is user-safe."""


class BillingNotConfigured(BillingError):
    """Stripe keys are unset; billing endpoints should report as unavailable."""


def _client() -> stripe.StripeClient:
    settings = get_settings()
    if not settings.stripe_secret_key:
        raise BillingNotConfigured("Billing is not configured on this deployment.")
    return stripe.StripeClient(settings.stripe_secret_key)


def _to_datetime(value: Any) -> datetime | None:
    """Convert a Stripe unix timestamp to an aware datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        return datetime.fromtimestamp(int(value), tz=UTC)
    except (TypeError, ValueError, OSError):
        return None


# --------------------------------------------------------------------------
# Customers and checkout
# --------------------------------------------------------------------------


def get_customer(db: Session, nonprofit_id: int) -> Customer | None:
    return db.scalar(select(Customer).where(Customer.nonprofit_id == nonprofit_id))


def ensure_customer(
    db: Session, nonprofit: NonprofitModel, *, email: str | None = None
) -> Customer:
    """Return the tenant's Stripe customer, creating one if needed.

    Stored back to the database immediately so a crash between the Stripe call
    and the commit cannot produce a second customer on the next attempt.
    """
    existing = get_customer(db, nonprofit.id)
    if existing is not None:
        return existing

    client = _client()
    created = client.customers.create(
        {
            "name": nonprofit.name,
            "email": email or None,
            # The tenant id is how a human reconciles a Stripe dashboard row
            # back to an account without exposing our internal user emails.
            "metadata": {"nonprofit_id": str(nonprofit.id), "slug": nonprofit.slug},
        }
    )

    customer = Customer(
        nonprofit_id=nonprofit.id,
        stripe_customer_id=created["id"],
        email=email,
    )
    db.add(customer)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        found = get_customer(db, nonprofit.id)
        if found is None:
            raise
        return found
    return customer


def create_checkout_session(
    db: Session,
    *,
    nonprofit: NonprofitModel,
    plan_key: str,
    success_url: str,
    cancel_url: str,
    email: str | None = None,
) -> str:
    """Create a Stripe Checkout session and return its URL.

    The price is resolved from *our* configured price ID for the requested
    plan. The client never supplies an amount, so a tampered request cannot buy
    enterprise for a dollar.
    """
    settings = get_settings()
    price_id = settings.stripe_price_ids.get(plan_key)
    if not price_id:
        raise BillingError("That plan is not available for purchase.")

    customer = ensure_customer(db, nonprofit, email=email)

    session = _client().checkout.sessions.create(
        {
            "mode": "subscription",
            "customer": customer.stripe_customer_id,
            "line_items": [{"price": price_id, "quantity": 1}],
            "success_url": success_url,
            "cancel_url": cancel_url,
            "client_reference_id": str(nonprofit.id),
            # Duplicated into metadata so the webhook can attribute the
            # subscription even if the customer object is missing from the
            # expanded payload.
            "subscription_data": {
                "metadata": {"nonprofit_id": str(nonprofit.id), "plan_key": plan_key}
            },
            "metadata": {"nonprofit_id": str(nonprofit.id), "plan_key": plan_key},
            "allow_promotion_codes": True,
        }
    )
    db.flush()
    return session["url"]


def create_portal_session(
    db: Session, *, nonprofit: NonprofitModel, return_url: str
) -> str:
    """Create a Stripe Billing Portal session so a tenant manages its own card."""
    customer = get_customer(db, nonprofit.id)
    if customer is None:
        raise BillingError("This account has no billing profile yet.")
    session = _client().billing_portal.sessions.create(
        {"customer": customer.stripe_customer_id, "return_url": return_url}
    )
    return session["url"]


# --------------------------------------------------------------------------
# Webhooks
# --------------------------------------------------------------------------


def verify_webhook(payload: bytes, signature_header: str | None) -> dict[str, Any]:
    """Verify a webhook signature and return the parsed event.

    The ``payload`` must be the exact bytes received. Parsing the body first
    and re-encoding it would change the bytes and break the check, which is why
    the route reads the raw request body.
    """
    settings = get_settings()
    secret = settings.stripe_webhook_secret
    if not secret:
        raise BillingNotConfigured("Webhook secret is not configured.")
    if not signature_header:
        raise BillingError("Missing signature.")

    try:
        return stripe.Webhook.construct_event(payload, signature_header, secret)
    except stripe.SignatureVerificationError as exc:
        # Do not echo the reason: a signature oracle helps an attacker.
        logger.warning("stripe webhook signature verification failed")
        raise BillingError("Invalid signature.") from exc
    except ValueError as exc:
        raise BillingError("Invalid payload.") from exc


def apply_event(db: Session, event: dict[str, Any]) -> str:
    """Apply one verified Stripe event. Returns a short outcome string.

    Idempotency is enforced by inserting the event ID first: if that insert
    conflicts, the event was already handled and we stop. Doing the insert
    before the side effect means a crash mid-handler leaves the event marked as
    processed rather than replaying it, which is the safer failure for billing.
    """
    event_id = event.get("id") or ""
    event_type = event.get("type") or ""
    if not event_id:
        raise BillingError("Event is missing an id.")

    marker = WebhookEvent(stripe_event_id=event_id, event_type=event_type)
    db.add(marker)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        logger.info("stripe webhook replay ignored id=%s", event_id)
        return "duplicate"

    try:
        obj = (event.get("data") or {}).get("object") or {}
        handler = _HANDLERS.get(event_type)
        if handler is None:
            outcome = "ignored"
        else:
            outcome = handler(db, obj)
        db.flush()
        return outcome
    except Exception as exc:
        # Record the failure on the marker so an operator can find and replay
        # it, then re-raise so Stripe retries with backoff.
        marker.error = f"{type(exc).__name__}: {exc}"[:1000]
        db.flush()
        logger.error("stripe webhook handler failed type=%s id=%s", event_type, event_id)
        raise


def _nonprofit_id_from(obj: dict[str, Any]) -> int | None:
    """Extract the tenant id from a Stripe object's metadata."""
    metadata = obj.get("metadata") or {}
    raw = metadata.get("nonprofit_id") or obj.get("client_reference_id")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _customer_for(db: Session, obj: dict[str, Any]) -> Customer | None:
    """Find our customer row from a Stripe customer id on the object."""
    stripe_customer_id = obj.get("customer")
    if not stripe_customer_id:
        return None
    return db.scalar(
        select(Customer).where(Customer.stripe_customer_id == stripe_customer_id)
    )


def _upsert_subscription(
    db: Session, customer: Customer, obj: dict[str, Any]
) -> Subscription:
    """Create or update the local mirror of a Stripe subscription."""
    settings = get_settings()
    stripe_sub_id = obj.get("id")
    if not stripe_sub_id:
        raise BillingError("Subscription payload has no id.")

    record = db.scalar(
        select(Subscription).where(Subscription.stripe_subscription_id == stripe_sub_id)
    )
    if record is None:
        record = Subscription(
            customer_id=customer.id,
            stripe_subscription_id=stripe_sub_id,
        )
        db.add(record)

    items = ((obj.get("items") or {}).get("data")) or []
    price_id = None
    if items:
        price_id = ((items[0].get("price") or {}).get("id")) or None

    # Plan comes from our configured price map. Metadata is only a fallback for
    # a subscription created out-of-band in the Stripe dashboard.
    plan_key = plan_from_price_id(price_id, settings.stripe_price_ids_inverted)
    if not price_id:
        plan_key = (obj.get("metadata") or {}).get("plan_key") or DEFAULT_PLAN

    record.stripe_price_id = price_id
    record.plan_key = plan_key
    record.status = obj.get("status") or record.status
    record.current_period_start = _to_datetime(obj.get("current_period_start"))
    record.current_period_end = _to_datetime(obj.get("current_period_end"))
    record.cancel_at_period_end = bool(obj.get("cancel_at_period_end"))
    record.canceled_at = _to_datetime(obj.get("canceled_at"))
    record.trial_end = _to_datetime(obj.get("trial_end"))
    record.raw_json = _safe_payload(obj)
    db.flush()
    return record


def _safe_payload(obj: dict[str, Any]) -> dict[str, Any]:
    """Store a trimmed copy of the Stripe payload.

    Kept small deliberately: a full subscription object is large, and nothing
    in the application reads fields beyond those mirrored into columns.
    """
    keep = (
        "id", "status", "customer", "current_period_start", "current_period_end",
        "cancel_at_period_end", "canceled_at", "trial_end", "created",
    )
    trimmed = {k: obj.get(k) for k in keep if k in obj}
    items = ((obj.get("items") or {}).get("data")) or []
    if items:
        trimmed["price_id"] = (items[0].get("price") or {}).get("id")
    return trimmed


# -- handlers ---------------------------------------------------------------


def _handle_subscription_created(db: Session, obj: dict[str, Any]) -> str:
    customer = _customer_for(db, obj)
    if customer is None:
        np_id = _nonprofit_id_from(obj)
        if np_id is not None:
            customer = get_customer(db, np_id)
    if customer is None:
        logger.warning("subscription created for unknown customer; storing nothing")
        return "unknown_customer"
    _upsert_subscription(db, customer, obj)
    return "subscription_upserted"


def _handle_subscription_updated(db: Session, obj: dict[str, Any]) -> str:
    customer = _customer_for(db, obj)
    if customer is None:
        return "unknown_customer"
    _upsert_subscription(db, customer, obj)
    return "subscription_updated"


def _handle_subscription_deleted(db: Session, obj: dict[str, Any]) -> str:
    customer = _customer_for(db, obj)
    if customer is None:
        return "unknown_customer"
    record = _upsert_subscription(db, customer, obj)
    # Mark terminal explicitly rather than trusting the payload's status field,
    # which historically differs between API versions.
    record.status = "canceled"
    db.flush()
    return "subscription_canceled"


def _handle_checkout_completed(db: Session, obj: dict[str, Any]) -> str:
    """Attach the tenant to the customer Stripe just created at checkout.

    Checkout can create the customer, so this is where our row is most reliably
    linked. ``ensure_customer`` already created one, but this handles the
    case where the subscription was created through the Stripe dashboard.
    """
    stripe_customer_id = obj.get("customer")
    np_id = _nonprofit_id_from(obj)
    if not stripe_customer_id or np_id is None:
        return "ignored"

    customer = get_customer(db, np_id)
    if customer is None:
        customer = Customer(
            nonprofit_id=np_id,
            stripe_customer_id=stripe_customer_id,
            email=(obj.get("customer_details") or {}).get("email"),
        )
        db.add(customer)
        db.flush()
    elif customer.stripe_customer_id != stripe_customer_id:
        # A second customer for one tenant would split billing history; log it
        # rather than silently rewriting the pointer.
        logger.warning(
            "checkout customer mismatch np=%s have=%s got=%s",
            np_id,
            customer.stripe_customer_id,
            stripe_customer_id,
        )
    return "checkout_linked"


def _handle_invoice_payment_failed(db: Session, obj: dict[str, Any]) -> str:
    customer = _customer_for(db, obj)
    if customer is None:
        return "unknown_customer"
    stripe_sub_id = obj.get("subscription")
    if not stripe_sub_id:
        return "no_subscription"
    record = db.scalar(
        select(Subscription).where(Subscription.stripe_subscription_id == stripe_sub_id)
    )
    if record is None:
        return "no_subscription"
    record.status = "past_due"
    db.flush()
    logger.info("invoice payment failed np=%s", customer.nonprofit_id)
    return "marked_past_due"


_HANDLERS = {
    "customer.subscription.created": _handle_subscription_created,
    "customer.subscription.updated": _handle_subscription_updated,
    "customer.subscription.deleted": _handle_subscription_deleted,
    "checkout.session.completed": _handle_checkout_completed,
    "invoice.payment_failed": _handle_invoice_payment_failed,
}


# --------------------------------------------------------------------------
# Plan resolution for a tenant
# --------------------------------------------------------------------------


def current_plan_key(db: Session, nonprofit_id: int) -> str:
    """The plan key that currently governs a tenant.

    Falls back to the free tier when there is no active subscription, so a
    lapsed card downgrades access rather than erroring.
    """
    customer = get_customer(db, nonprofit_id)
    if customer is None:
        return DEFAULT_PLAN

    record = db.scalar(
        select(Subscription)
        .where(
            Subscription.customer_id == customer.id,
            Subscription.status.in_(tuple(ACTIVE_STRIPE_STATUSES)),
        )
        .order_by(Subscription.updated_at.desc())
    )
    if record is None:
        return DEFAULT_PLAN
    return record.plan_key or DEFAULT_PLAN


__all__ = [
    "BillingError",
    "BillingNotConfigured",
    "apply_event",
    "create_checkout_session",
    "create_portal_session",
    "current_plan_key",
    "ensure_customer",
    "get_customer",
    "verify_webhook",
]