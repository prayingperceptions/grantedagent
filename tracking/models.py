"""Usage events and the audit trail.

Two different jobs, kept in two tables because they have different retention,
different access rules and different failure modes.

``usage_events`` is a product-analytics stream: what did this tenant do, how
much of their quota did it cost. High volume, safe to aggregate, prunable.

``audit_events`` is a compliance record: who changed what, when, from where.
Append-only, never pruned on a whim, and written for privileged actions even
when the action fails - a failed privilege escalation is exactly the event an
investigator wants to see.

Neither table is a substitute for the other. Losing usage history degrades a
dashboard; losing the audit trail destroys the ability to answer "who did this"
after an incident.
"""

from __future__ import annotations

import logging
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from hunter.models import Base, _utcnow

logger = logging.getLogger("tracking")

# SQLite only autoincrements a column declared exactly ``INTEGER PRIMARY KEY``;
# a BIGINT primary key there gets no rowid alias and every insert fails with a
# NOT NULL violation. The variant keeps BIGINT in PostgreSQL (where these
# event tables will outgrow 32 bits) and INTEGER in SQLite (tests). Defined
# once so both event tables stay in step.
BigPK = BigInteger().with_variant(Integer, "sqlite")

# Event names, centralised so a typo cannot silently create a second metric
# that looks empty on a dashboard.
EVENT_LOGIN = "auth.login"
EVENT_LOGOUT = "auth.logout"
EVENT_SIGNUP = "auth.signup"
EVENT_PASSWORD_RESET = "auth.password_reset"
EVENT_TOKEN_CREATED = "auth.api_token_created"
EVENT_TOKEN_REVOKED = "auth.api_token_revoked"

EVENT_HUNT_RUN = "hunter.run"
EVENT_GRANT_VIEWED = "grants.viewed"
EVENT_MATCH_VIEWED = "matches.viewed"
EVENT_MATCH_REVIEWED = "matches.reviewed"
EVENT_DRAFT_GENERATED = "drafts.generated"
EVENT_DRAFT_EXPORTED = "drafts.exported"
EVENT_SOUL_UPDATED = "soul.updated"

EVENT_MEMBER_INVITED = "members.invited"
EVENT_MEMBER_ROLE_CHANGED = "members.role_changed"
EVENT_MEMBER_REMOVED = "members.removed"

EVENT_PLAN_CHANGED = "billing.plan_changed"
EVENT_CHECKOUT_STARTED = "billing.checkout_started"


class UsageEvent(Base):
    """A metered or analytical event, attributed to a tenant and a user."""

    __tablename__ = "usage_events"

    id: Mapped[int] = mapped_column(BigPK, primary_key=True, autoincrement=True)

    # Nullable so pre-tenant events (a failed login for an unknown address) are
    # still recordable without inventing a tenant.
    nonprofit_id: Mapped[int | None] = mapped_column(
        ForeignKey("nonprofits.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )

    name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # Counts usage for quota maths; 1 for a single action, N for a batch.
    quantity: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Free-form context. Must never contain secrets, tokens or raw soul
    # content - the scrubbing boundary lives in tracking.service.
    properties: Mapped[dict[str, Any] | None] = mapped_column(JSON)

    ip: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )

    __table_args__ = (
        Index("ix_usage_events_np_name_created", "nonprofit_id", "name", "created_at"),
        Index("ix_usage_events_name_created", "name", "created_at"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<UsageEvent {self.name} np={self.nonprofit_id}>"


class AuditEvent(Base):
    """An append-only record of a security-relevant action.

    ``actor_email`` is denormalised on purpose: the audit trail must still name
    the actor after the user row is deleted, which is precisely when an audit
    trail is most likely to be consulted.
    """

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(BigPK, primary_key=True, autoincrement=True)

    nonprofit_id: Mapped[int | None] = mapped_column(
        ForeignKey("nonprofits.id", ondelete="SET NULL"), index=True
    )
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    actor_email: Mapped[str | None] = mapped_column(String(320))

    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(64))

    # "success" or "failure". Recorded on failure too, because a burst of
    # failed privileged actions is a signal worth keeping.
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="success")

    detail: Mapped[str | None] = mapped_column(Text)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )

    __table_args__ = (
        Index("ix_audit_events_np_created", "nonprofit_id", "created_at"),
        Index("ix_audit_events_action_created", "action", "created_at"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<AuditEvent {self.action} {self.outcome} np={self.nonprofit_id}>"


class DailyUsage(Base):
    """Per-tenant daily rollup.

    Maintained alongside the raw stream so a quota check is one row read rather
    than an aggregate over millions of events. The rollup is derived data: if
    it is ever wrong, it can be rebuilt from ``usage_events``.
    """

    __tablename__ = "daily_usage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    nonprofit_id: Mapped[int] = mapped_column(
        ForeignKey("nonprofits.id", ondelete="CASCADE"), nullable=False, index=True
    )
    day: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    event_name: Mapped[str] = mapped_column(String(64), nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        Index("uq_daily_usage_np_day_name", "nonprofit_id", "day", "event_name", unique=True),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<DailyUsage np={self.nonprofit_id} {self.day} {self.event_name}={self.count}>"


__all__ = [
    "EVENT_CHECKOUT_STARTED",
    "EVENT_DRAFT_EXPORTED",
    "EVENT_DRAFT_GENERATED",
    "EVENT_GRANT_VIEWED",
    "EVENT_HUNT_RUN",
    "EVENT_LOGIN",
    "EVENT_LOGOUT",
    "EVENT_MATCH_REVIEWED",
    "EVENT_MATCH_VIEWED",
    "EVENT_MEMBER_INVITED",
    "EVENT_MEMBER_REMOVED",
    "EVENT_MEMBER_ROLE_CHANGED",
    "EVENT_PASSWORD_RESET",
    "EVENT_PLAN_CHANGED",
    "EVENT_SIGNUP",
    "EVENT_SOUL_UPDATED",
    "EVENT_TOKEN_CREATED",
    "EVENT_TOKEN_REVOKED",
    "AuditEvent",
    "DailyUsage",
    "UsageEvent",
]