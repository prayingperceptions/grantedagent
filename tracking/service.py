"""Recording usage and audit events.

The important design choice is :func:`_scrub`. Event properties are written by
callers all over the codebase, and the natural thing to pass is "the thing I
just handled" - which is sometimes a token, a soul body, or an API key. Rather
than rely on every caller remembering, the scrubbing boundary sits here, in the
one function through which all events pass.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from tracking.models import (
    EVENT_CHECKOUT_STARTED,
    EVENT_DRAFT_EXPORTED,
    EVENT_DRAFT_GENERATED,
    EVENT_GRANT_VIEWED,
    EVENT_HUNT_RUN,
    EVENT_LOGIN,
    EVENT_LOGOUT,
    EVENT_MATCH_REVIEWED,
    EVENT_MATCH_VIEWED,
    EVENT_MEMBER_INVITED,
    EVENT_MEMBER_REMOVED,
    EVENT_MEMBER_ROLE_CHANGED,
    EVENT_PASSWORD_RESET,
    EVENT_PLAN_CHANGED,
    EVENT_SIGNUP,
    EVENT_SOUL_UPDATED,
    EVENT_TOKEN_CREATED,
    EVENT_TOKEN_REVOKED,
    AuditEvent,
    DailyUsage,
    UsageEvent,
)

logger = logging.getLogger("tracking")

# Keys whose values are never safe to persist, matched case-insensitively as
# substrings so ``api_key``, ``stripe_secret_key`` and ``X-Api-Key`` all match.
_SENSITIVE_KEY_PARTS = (
    "password", "passwd", "secret", "token", "api_key", "apikey", "authorization",
    "auth", "credential", "private_key", "session", "cookie", "soul", "ein",
    "signature", "card", "cvc", "iban", "account_number",
)

_REDACTED = "[redacted]"

# Properties are for small context, not documents. Anything larger is a sign
# that a caller is trying to stash a payload where it does not belong.
MAX_PROPERTY_DEPTH = 4
MAX_STRING_LENGTH = 512


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in _SENSITIVE_KEY_PARTS)


def _scrub_value(value: Any, depth: int) -> Any:
    """Coerce a value into something safe to persist."""
    if depth > MAX_PROPERTY_DEPTH:
        return "[truncated]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:MAX_STRING_LENGTH]
    if isinstance(value, dict):
        return _scrub_mapping(value, depth + 1)
    if isinstance(value, (list, tuple, set)):
        return [_scrub_value(v, depth + 1) for v in list(value)[:50]]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    # Anything else (an ORM object, a bytes blob, a custom class) is not
    # something we can meaningfully persist or safely inspect.
    return f"<{type(value).__name__}>"


def _scrub_mapping(mapping: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in mapping.items():
        key_str = str(key)[:64]
        if _is_sensitive(key_str):
            out[key_str] = _REDACTED
        else:
            out[key_str] = _scrub_value(value, depth)
    return out


def scrub(properties: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return a copy of ``properties`` safe to store and later display."""
    if not properties:
        return None
    return _scrub_mapping(properties)


# --------------------------------------------------------------------------
# Usage
# --------------------------------------------------------------------------


def record_usage(
    db: Session,
    *,
    name: str,
    nonprofit_id: int | None = None,
    user_id: int | None = None,
    quantity: int = 1,
    ip: str | None = None,
    properties: dict[str, Any] | None = None,
    rollup: bool = True,
) -> UsageEvent:
    """Append a usage event, and optionally update the daily rollup.

    Telemetry must never be the reason a user's action fails, so a failure to
    write the rollup is logged and swallowed; the raw event is what matters and
    the rollup can be rebuilt from it.
    """
    event = UsageEvent(
        nonprofit_id=nonprofit_id,
        user_id=user_id,
        name=name[:64],
        quantity=max(1, int(quantity)),
        properties=scrub(properties),
        ip=(ip or None) and ip[:64],
    )
    db.add(event)
    db.flush()

    if rollup and nonprofit_id is not None:
        try:
            bump_rollup(db, nonprofit_id=nonprofit_id, name=event.name, amount=event.quantity)
        except Exception:  # pragma: no cover - defensive
            logger.warning("usage rollup failed name=%s", name, exc_info=True)
    return event


def bump_rollup(
    db: Session, *, nonprofit_id: int, name: str, amount: int = 1, day: date | None = None
) -> None:
    """Increment the per-day counter, inserting the row if it is new.

    Written as an upsert so concurrent requests for the same tenant and day
    cannot lose a count or violate the unique index.
    """
    day = day or datetime.now(UTC).date()
    dialect = db.bind.dialect.name if db.bind is not None else ""

    if dialect == "postgresql":
        db.execute(
            text(
                """
                INSERT INTO daily_usage (nonprofit_id, day, event_name, count)
                VALUES (:np, :day, :name, :amount)
                ON CONFLICT (nonprofit_id, day, event_name)
                DO UPDATE SET count = daily_usage.count + EXCLUDED.count
                """
            ),
            {"np": nonprofit_id, "day": day, "name": name, "amount": amount},
        )
        db.flush()
        return

    # Portable fallback (SQLite in tests): try the update, then insert.
    existing = db.scalar(
        select(DailyUsage).where(
            DailyUsage.nonprofit_id == nonprofit_id,
            DailyUsage.day == day,
            DailyUsage.event_name == name,
        )
    )
    if existing is not None:
        existing.count += amount
        db.flush()
        return

    db.add(
        DailyUsage(nonprofit_id=nonprofit_id, day=day, event_name=name, count=amount)
    )
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        bump_rollup(db, nonprofit_id=nonprofit_id, name=name, amount=amount, day=day)


def usage_totals(
    db: Session,
    *,
    nonprofit_id: int,
    name: str | None = None,
    since: datetime | None = None,
) -> dict[str, int]:
    """Total usage per event name for a tenant. Always scoped to one tenant."""
    stmt = (
        select(UsageEvent.name, func.coalesce(func.sum(UsageEvent.quantity), 0))
        .where(UsageEvent.nonprofit_id == nonprofit_id)
        .group_by(UsageEvent.name)
    )
    if name:
        stmt = stmt.where(UsageEvent.name == name)
    if since:
        stmt = stmt.where(UsageEvent.created_at >= since)
    return {row[0]: int(row[1]) for row in db.execute(stmt)}


def count_usage_since(
    db: Session, *, nonprofit_id: int, name: str, since: datetime
) -> int:
    """How much of ``name`` this tenant has consumed since ``since``.

    Reads ``nonprofit_id`` from the caller's :class:`TenantScope`, never from
    request input.
    """
    total = db.scalar(
        select(func.coalesce(func.sum(UsageEvent.quantity), 0)).where(
            UsageEvent.nonprofit_id == nonprofit_id,
            UsageEvent.name == name,
            UsageEvent.created_at >= since,
        )
    )
    return int(total or 0)


def recent_events(
    db: Session, *, nonprofit_id: int, limit: int = 50
) -> list[UsageEvent]:
    return list(
        db.scalars(
            select(UsageEvent)
            .where(UsageEvent.nonprofit_id == nonprofit_id)
            .order_by(UsageEvent.created_at.desc(), UsageEvent.id.desc())
            .limit(min(limit, 500))
        )
    )


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------


def record_audit(
    db: Session,
    *,
    action: str,
    nonprofit_id: int | None = None,
    actor_user_id: int | None = None,
    actor_email: str | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    outcome: str = "success",
    detail: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
) -> AuditEvent:
    """Append an audit record.

    ``detail`` is truncated rather than scrubbed: it is written by developers,
    not derived from user input, and a truncated message is still useful. Never
    pass a token or a password into it.
    """
    event = AuditEvent(
        nonprofit_id=nonprofit_id,
        actor_user_id=actor_user_id,
        actor_email=(actor_email or None) and actor_email[:320],
        action=action[:64],
        target_type=(target_type or None) and target_type[:64],
        target_id=None if target_id is None else str(target_id)[:64],
        outcome=outcome[:16],
        detail=(detail or None) and detail[:2000],
        ip=(ip or None) and ip[:64],
        user_agent=(user_agent or None) and user_agent[:500],
    )
    db.add(event)
    db.flush()
    return event


def recent_audit(
    db: Session, *, nonprofit_id: int, limit: int = 50
) -> list[AuditEvent]:
    return list(
        db.scalars(
            select(AuditEvent)
            .where(AuditEvent.nonprofit_id == nonprofit_id)
            .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
            .limit(min(limit, 500))
        )
    )


def record_many_usage(
    db: Session, events: Iterable[dict[str, Any]]
) -> list[UsageEvent]:
    """Record several usage events in one call, for batch operations."""
    return [record_usage(db, **event) for event in events]


__all__ = [
    "record_usage",
    "bump_rollup",
    "usage_totals",
    "count_usage_since",
    "recent_events",
    "record_audit",
    "recent_audit",
    "record_many_usage",
    "scrub",
    "REDACTED",
    # Event name constants, re-exported so callers use one import.
    "EVENT_SIGNUP",
    "EVENT_LOGIN",
    "EVENT_LOGOUT",
    "EVENT_PASSWORD_RESET",
    "EVENT_TOKEN_CREATED",
    "EVENT_TOKEN_REVOKED",
    "EVENT_HUNT_RUN",
    "EVENT_GRANT_VIEWED",
    "EVENT_MATCH_VIEWED",
    "EVENT_MATCH_REVIEWED",
    "EVENT_DRAFT_GENERATED",
    "EVENT_DRAFT_EXPORTED",
    "EVENT_SOUL_UPDATED",
    "EVENT_MEMBER_INVITED",
    "EVENT_MEMBER_ROLE_CHANGED",
    "EVENT_MEMBER_REMOVED",
    "EVENT_PLAN_CHANGED",
    "EVENT_CHECKOUT_STARTED",
]

REDACTED = _REDACTED