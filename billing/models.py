"""Billing models.

Only the *payment* state lives here; what a plan permits lives in
``billing.plans``.

Amounts are stored in the smallest currency unit (cents) as integers. Storing
money as a float is a classic source of off-by-a-cent drift, and an integer
cent count is exactly what Stripe's API uses, so no conversion is needed at the
boundary.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from hunter.models import Base, _utcnow

# Mirrors Stripe's subscription status vocabulary so no translation layer is
# needed and an unknown value from Stripe is stored verbatim.
STATUS_ACTIVE = "active"
STATUS_TRIALING = "trialing"
STATUS_PAST_DUE = "past_due"
STATUS_CANCELED = "canceled"
STATUS_UNPAID = "unpaid"
STATUS_INCOMPLETE = "incomplete"
STATUS_INCOMPLETE_EXPIRED = "incomplete_expired"
STATUS_PAUSED = "paused"
STATUS_NONE = "none"


class Customer(Base):
    """The Stripe customer for a nonprofit (tenant).

    One customer per tenant, not per user: the nonprofit owns the subscription,
    so staff turnover must not affect billing.
    """

    __tablename__ = "billing_customers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    nonprofit_id: Mapped[int] = mapped_column(
        ForeignKey("nonprofits.id", ondelete="CASCADE"), nullable=False, unique=True, index=True
    )

    stripe_customer_id: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True, index=True
    )
    email: Mapped[str | None] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    subscriptions: Mapped[list[Subscription]] = relationship(
        back_populates="customer", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Customer np={self.nonprofit_id} stripe={self.stripe_customer_id}>"


class Subscription(Base):
    """A subscription record, mirrored from Stripe webhooks.

    The local row is a cache of Stripe's state, not an authority. It exists so
    a page render does not require a Stripe API call, and it is always
    reconciled from webhooks, which are the only events that carry the
    signature proving they came from Stripe.
    """

    __tablename__ = "billing_subscriptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    customer_id: Mapped[int] = mapped_column(
        ForeignKey("billing_customers.id", ondelete="CASCADE"), nullable=False, index=True
    )

    stripe_subscription_id: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True, index=True
    )
    stripe_price_id: Mapped[str | None] = mapped_column(String(255))
    plan_key: Mapped[str] = mapped_column(String(32), nullable=False, default="community")

    status: Mapped[str] = mapped_column(String(32), nullable=False, default=STATUS_NONE, index=True)

    current_period_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    canceled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    trial_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Raw Stripe payload for support and debugging. Never rendered to a user.
    raw_json: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    customer: Mapped[Customer] = relationship(back_populates="subscriptions")

    __table_args__ = (
        Index("ix_billing_subscriptions_customer_status", "customer_id", "status"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Subscription {self.plan_key} {self.status}>"


class WebhookEvent(Base):
    """Processed Stripe webhook IDs, for idempotency.

    Stripe retries webhooks and can deliver the same event more than once. The
    unique constraint on ``stripe_event_id`` is what makes replay harmless:
    the second delivery hits the constraint instead of, say, extending a
    subscription period a second time.
    """

    __tablename__ = "billing_webhook_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    stripe_event_id: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True, index=True
    )
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    processed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    error: Mapped[str | None] = mapped_column(Text)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<WebhookEvent {self.event_type} {self.stripe_event_id}>"


__all__ = [
    "STATUS_ACTIVE",
    "STATUS_CANCELED",
    "STATUS_INCOMPLETE",
    "STATUS_INCOMPLETE_EXPIRED",
    "STATUS_NONE",
    "STATUS_PAST_DUE",
    "STATUS_PAUSED",
    "STATUS_TRIALING",
    "STATUS_UNPAID",
    "Customer",
    "Subscription",
    "WebhookEvent",
]