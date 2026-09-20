"""ORM models for the Hunter.

The `grants` table is the single landing zone for every source. `source`
describes provenance at three levels:

    federal              - a federal agency (grants.gov / simpler / sam.gov)
    national_foundation  - a US-wide private foundation
    state_CA             - a state program, suffixed with the two letter code

`state_code` is nullable because federal and national foundation grants are
not state scoped. It carries the explicit code in the ``state_XX`` columns.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Date,
    DateTime,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

try:  # pgvector is optional at import time so sqlite tests still run.
    from pgvector.sqlalchemy import Vector

    _VECTOR = True
except Exception:  # pragma: no cover - exercised only without pgvector
    Vector = None  # type: ignore[assignment]
    _VECTOR = False

SOURCE_FEDERAL = "federal"
SOURCE_NATIONAL_FOUNDATION = "national_foundation"
SOURCE_STATE_PREFIX = "state_"

EMBEDDING_DIM = 1536


class Base(DeclarativeBase):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Grant(Base):
    __tablename__ = "grants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    external_id: Mapped[str | None] = mapped_column(String(255), index=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    agency: Mapped[str | None] = mapped_column(Text)
    deadline: Mapped[date | None] = mapped_column(Date, index=True)
    amount_min: Mapped[float | None] = mapped_column(Numeric(16, 2))
    amount_max: Mapped[float | None] = mapped_column(Numeric(16, 2))
    description: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(Text)
    raw_json: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    # federal | national_foundation | state_CA
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    state_code: Mapped[str | None] = mapped_column(String(2), index=True)
    dedupe_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    # Postgres only; the column is added by migration when pgvector is present.
    embedding: Mapped[Any | None] = mapped_column(
        Vector(EMBEDDING_DIM) if _VECTOR else JSON, nullable=True
    )

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    __table_args__ = (
        UniqueConstraint("dedupe_hash", name="uq_grants_dedupe_hash"),
        Index("ix_grants_source_state", "source", "state_code"),
        Index("ix_grants_deadline_source", "deadline", "source"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Grant {self.source}:{self.external_id} {self.title[:40]!r}>"


class HunterRun(Base):
    """One row per scheduler tick; keeps the found/breakdown counters auditable."""

    __tablename__ = "hunter_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    federal_found: Mapped[int] = mapped_column(Integer, default=0)
    foundation_found: Mapped[int] = mapped_column(Integer, default=0)
    state_total: Mapped[int] = mapped_column(Integer, default=0)
    state_breakdown: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    errors: Mapped[dict[str, Any] | None] = mapped_column(JSON)


__all__ = [
    "Base",
    "Grant",
    "HunterRun",
    "SOURCE_FEDERAL",
    "SOURCE_NATIONAL_FOUNDATION",
    "SOURCE_STATE_PREFIX",
    "EMBEDDING_DIM",
]