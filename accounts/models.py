"""Identity and access models.

Tenancy is expressed through :class:`Membership` rather than an ``owner_id``
column on ``nonprofits``. A join table is the right shape because a fiscal
sponsor legitimately needs one human to hold access to several nonprofits, and
a nonprofit legitimately needs several humans; an owner column models neither
and forces a schema change the first time a board member needs access.

Access is always resolved *through* a membership row. There is no query in this
codebase that reaches tenant data without first establishing a membership, so
"which tenant is this request for" is answered in exactly one place.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from hunter.models import Base, _utcnow

# SQLite only autoincrements a column declared exactly ``INTEGER PRIMARY KEY``;
# a BIGINT primary key there gets no rowid alias and every insert fails with a
# NOT NULL violation. This variant keeps BIGINT on PostgreSQL (where the
# high-volume tables will outgrow 32 bits) and INTEGER on SQLite (tests).
BigPK = BigInteger().with_variant(Integer, "sqlite")

# Ordered least to most privileged. Comparisons use ROLE_RANK, never string
# ordering, so adding a role cannot silently change an authorisation result.
ROLE_VIEWER = "viewer"
ROLE_MEMBER = "member"
ROLE_ADMIN = "admin"
ROLE_OWNER = "owner"

ROLE_RANK: dict[str, int] = {
    ROLE_VIEWER: 10,
    ROLE_MEMBER: 20,
    ROLE_ADMIN: 30,
    ROLE_OWNER: 40,
}

# Roles a human may hold. Billing admin is folded into owner so a single role
# governs "can change the payment method".
ASSIGNABLE_ROLES = (ROLE_VIEWER, ROLE_MEMBER, ROLE_ADMIN, ROLE_OWNER)


def rank(role: str) -> int:
    return ROLE_RANK.get(role, 0)


def outranks(actor: str, target: str) -> bool:
    """True when ``actor`` holds strictly more privilege than ``target``.

    Strict on purpose: an admin must not be able to demote or remove a peer
    admin, which would let two compromised admin accounts escalate.
    """
    return rank(actor) > rank(target)


class User(Base):
    """A human account. Distinct from :class:`NonprofitModel` (a tenant)."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Stored lowercased. The unique index is therefore case-insensitive in
    # practice; the normalisation happens in one place (accounts/service.py) so
    # "Alice@x.com" and "alice@x.com" cannot both be registered.
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)

    password_hash: Mapped[str] = mapped_column(Text, nullable=False)

    full_name: Mapped[str | None] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_staff: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Set once the email address is confirmed. Signup issues a token; login is
    # permitted before verification so a mail outage cannot lock everyone out,
    # but sensitive actions require it.
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    memberships: Mapped[list[Membership]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        # Membership has two foreign keys to users (user_id and invited_by_id),
        # so the join path has to be stated explicitly.
        foreign_keys="Membership.user_id",
    )
    sessions: Mapped[list[UserSession]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    api_tokens: Mapped[list[ApiToken]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<User {self.id} {self.email}>"


class Membership(Base):
    """Grants a user a role within one nonprofit. The tenancy join."""

    __tablename__ = "memberships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    nonprofit_id: Mapped[int] = mapped_column(
        ForeignKey("nonprofits.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False, default=ROLE_MEMBER)

    invited_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    user: Mapped[User] = relationship(back_populates="memberships", foreign_keys=[user_id])

    __table_args__ = (
        UniqueConstraint("user_id", "nonprofit_id", name="uq_memberships_user_nonprofit"),
        Index("ix_memberships_nonprofit_role", "nonprofit_id", "role"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Membership u={self.user_id} np={self.nonprofit_id} {self.role}>"


class UserSession(Base):
    """A browser session. The raw token exists only in the client's cookie."""

    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # SHA-256 of the token. Never the token itself.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    user: Mapped[User] = relationship(back_populates="sessions")

    __table_args__ = (Index("ix_user_sessions_user_revoked", "user_id", "revoked_at"),)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<UserSession u={self.user_id} revoked={self.revoked_at is not None}>"


class ApiToken(Base):
    """A long-lived programmatic credential, scoped to one user."""

    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    prefix: Mapped[str] = mapped_column(String(16), nullable=False)

    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    user: Mapped[User] = relationship(back_populates="api_tokens")

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<ApiToken {self.prefix}... u={self.user_id}>"


class EmailToken(Base):
    """A single-use token for email verification or password reset.

    One table with a ``purpose`` discriminator, because the lifecycle is
    identical and a reset token must never be accepted where a verification
    token is expected - enforced by matching on ``purpose`` at lookup.
    """

    __tablename__ = "email_tokens"

    PURPOSE_VERIFY = "verify_email"
    PURPOSE_RESET = "reset_password"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (Index("ix_email_tokens_user_purpose", "user_id", "purpose"),)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<EmailToken {self.purpose} u={self.user_id}>"


class LoginAttempt(Base):
    """A record of a login attempt, for throttling and abuse review.

    The primary key is BIGINT on PostgreSQL because this table grows with
    traffic rather than with the customer count and will outgrow 32 bits, with
    an INTEGER variant so SQLite tests can autoincrement it (SQLite only treats
    a column declared exactly ``INTEGER PRIMARY KEY`` as a rowid alias).
    """

    __tablename__ = "login_attempts"

    id: Mapped[int] = mapped_column(BigPK, primary_key=True, autoincrement=True)

    # Kept even for unknown emails so credential-stuffing patterns against
    # many addresses are visible.
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    ip: Mapped[str | None] = mapped_column(String(64), index=True)
    succeeded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )

    __table_args__ = (Index("ix_login_attempts_email_created", "email", "created_at"),)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<LoginAttempt {self.email} ok={self.succeeded}>"


class WaitlistEntry(Base):
    """A lead captured by the marketing site's email form.

    Separate from :class:`User` because a lead has no credentials and must
    never be usable to sign in. Keeping the two apart means a bug in the
    marketing endpoint cannot create an account.
    """

    __tablename__ = "waitlist_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    source: Mapped[str | None] = mapped_column(String(64))
    ip: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<WaitlistEntry {self.email}>"


__all__ = [
    "ASSIGNABLE_ROLES",
    "ROLE_ADMIN",
    "ROLE_MEMBER",
    "ROLE_OWNER",
    "ROLE_RANK",
    "ROLE_VIEWER",
    "ApiToken",
    "EmailToken",
    "LoginAttempt",
    "Membership",
    "User",
    "UserSession",
    "WaitlistEntry",
    "outranks",
    "rank",
]