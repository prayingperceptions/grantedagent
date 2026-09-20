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
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

try:  # pgvector is optional at import time so sqlite tests still run.
    from pgvector.sqlalchemy import Vector

    _VECTOR = True
except Exception:  # pragma: no cover - exercised only without pgvector
    Vector = None  # type: ignore[assignment]
    _VECTOR = False

SOURCE_FEDERAL = "federal"
SOURCE_NATIONAL_FOUNDATION = "national_foundation"
SOURCE_STATE_PREFIX = "state_"

# all-MiniLM-L6-v2 emits 384-dimensional vectors. This must match the model
# exactly: pgvector rejects a mismatched insert ("expected 1536 dimensions,
# not 384"), so a wrong value here breaks scoring at write time rather than
# silently degrading.
EMBEDDING_DIM = 384

# Match lifecycle. A human moves a match out of NEEDS_REVIEW; nothing
# auto-approves.
STATUS_NEW = "NEW"
STATUS_NEEDS_REVIEW = "NEEDS_REVIEW"
STATUS_APPROVED = "APPROVED"
STATUS_REJECTED = "REJECTED"
MATCH_STATUSES = (STATUS_NEW, STATUS_NEEDS_REVIEW, STATUS_APPROVED, STATUS_REJECTED)


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


class NonprofitModel(Base):
    """A tenant: one nonprofit and its own soul-derived matching profile.

    Score and status cannot live on ``grants``: the same grant scores
    differently for every nonprofit. They belong on :class:`Match`, which is the
    join between the two.
    """

    __tablename__ = "nonprofits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    slug: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    ein: Mapped[str | None] = mapped_column(String(32))
    mission: Mapped[str | None] = mapped_column(Text)
    city: Mapped[str | None] = mapped_column(String(128))
    state: Mapped[str] = mapped_column(String(2), nullable=False, index=True)
    zip: Mapped[str | None] = mapped_column(String(16))
    country: Mapped[str] = mapped_column(String(2), default="US")

    # Parsed soul content. `raw` excludes secrets, which are stored encrypted.
    soul_json: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    soul_encrypted: Mapped[str | None] = mapped_column(Text)
    soul_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # The nonprofit's profile embedded for vector search. Same dimension as
    # grants.embedding so a single nearest-neighbour query can rank matches.
    embedding: Mapped[Any | None] = mapped_column(
        Vector(EMBEDDING_DIM) if _VECTOR else JSON, nullable=True
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    matches: Mapped[list["Match"]] = relationship(back_populates="nonprofit", cascade="all, delete-orphan")

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Nonprofit {self.slug} state={self.state}>"


class Match(Base):
    """Per-nonprofit scoring and review state for one grant."""

    __tablename__ = "matches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    nonprofit_id: Mapped[int] = mapped_column(
        ForeignKey("nonprofits.id", ondelete="CASCADE"), nullable=False, index=True
    )
    grant_id: Mapped[int] = mapped_column(
        ForeignKey("grants.id", ondelete="CASCADE"), nullable=False, index=True
    )

    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=STATUS_NEW, index=True)

    # Why the score came out where it did, so a user can audit a recommendation.
    rationale: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    similarity: Mapped[float | None] = mapped_column(Float)
    state_boost: Mapped[float | None] = mapped_column(Float)
    excluded: Mapped[bool] = mapped_column(Boolean, default=False)

    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reviewed_by: Mapped[str | None] = mapped_column(String(255))
    review_note: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    nonprofit: Mapped["NonprofitModel"] = relationship(back_populates="matches")
    grant: Mapped["Grant"] = relationship()
    drafts: Mapped[list["Draft"]] = relationship(back_populates="match", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("nonprofit_id", "grant_id", name="uq_matches_nonprofit_grant"),
        Index("ix_matches_nonprofit_score", "nonprofit_id", "score"),
        Index("ix_matches_status_score", "status", "score"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Match np={self.nonprofit_id} grant={self.grant_id} {self.score:.1f} {self.status}>"


class Draft(Base):
    """A generated document awaiting human review.

    Nothing here is auto-submitted; a draft exists to be edited and approved.
    """

    __tablename__ = "drafts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    match_id: Mapped[int] = mapped_column(
        ForeignKey("matches.id", ondelete="CASCADE"), nullable=False, index=True
    )

    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str | None] = mapped_column(Text)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    source_url: Mapped[str | None] = mapped_column(Text)

    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=STATUS_NEEDS_REVIEW, index=True
    )
    # Every field the template could not fill, so a human sees exactly what is
    # missing rather than a silently shortened document.
    missing_inputs: Mapped[list[Any] | None] = mapped_column(JSON)
    template_used: Mapped[str | None] = mapped_column(String(128))
    generator: Mapped[str | None] = mapped_column(String(64))

    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    match: Mapped["Match"] = relationship(back_populates="drafts")

    __table_args__ = (Index("ix_drafts_match_kind", "match_id", "kind"),)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Draft {self.kind} {self.status}>"


__all__ = [
    "Base",
    "Grant",
    "HunterRun",
    "NonprofitModel",
    "Match",
    "Draft",
    "SOURCE_FEDERAL",
    "SOURCE_NATIONAL_FOUNDATION",
    "SOURCE_STATE_PREFIX",
    "EMBEDDING_DIM",
    "STATUS_NEW",
    "STATUS_NEEDS_REVIEW",
    "STATUS_APPROVED",
    "STATUS_REJECTED",
    "MATCH_STATUSES",
]