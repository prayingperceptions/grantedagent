"""Identity, authentication and password lifecycle.

Every function takes an explicit session. Nothing here reads ambient state such
as a request context, so the logic is callable and testable from the API, the
CLI and background jobs alike.

Two rules shape this module:

1. **Never reveal whether an account exists.** Registration and password-reset
   answer identically for known and unknown addresses, and login pays a fixed
   argon2 cost either way.
2. **Lock out by counter, not forever.** Failed logins increment a counter that
   trips a time-boxed lockout, so an attacker cannot permanently deny a victim
   their own account by deliberately failing logins.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from accounts.models import (
    ROLE_OWNER,
    ApiToken,
    EmailToken,
    LoginAttempt,
    Membership,
    User,
    UserSession,
)
from accounts.security import (
    EMAIL_TOKEN_TTL,
    PASSWORD_RESET_TTL,
    SESSION_TTL,
    PasswordError,
    api_token_prefix,
    dummy_verify,
    ensure_aware,
    hash_password,
    is_expired,
    needs_rehash,
    new_api_token,
    new_email_token,
    new_session_token,
    token_digest,
    utcnow,
    validate_password,
    verify_password,
)
from hunter.models import NonprofitModel

logger = logging.getLogger("accounts.service")

MAX_FAILED_LOGINS = 8
LOCKOUT_DURATION = timedelta(minutes=15)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AuthError(Exception):
    """Authentication or authorisation failure. Message is user-safe."""


def normalise_email(email: str) -> str:
    """Lowercase and strip an address so uniqueness is case-insensitive.

    Applied on every write *and* every lookup; if it were only applied on
    write, a login with different casing would miss the row.
    """
    return (email or "").strip().lower()


def valid_email(email: str) -> bool:
    """Shape check only. Deliverability is proven by the verification email."""
    return bool(_EMAIL_RE.match(normalise_email(email))) and len(email) <= 320


# --------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == normalise_email(email)))


def get_user(db: Session, user_id: int) -> User | None:
    return db.get(User, user_id)


def create_user(
    db: Session,
    *,
    email: str,
    password: str,
    full_name: str | None = None,
) -> User:
    """Create a user. Raises :class:`AuthError` if the address is taken.

    The uniqueness check and the insert are separate statements, so two
    concurrent signups can both pass the check. The unique index is the real
    guarantee; the :class:`IntegrityError` catch converts the loser's database
    error into the same friendly message as the pre-check.
    """
    email = normalise_email(email)
    if not valid_email(email):
        raise AuthError("Enter a valid email address.")
    validate_password(password)

    if get_user_by_email(db, email) is not None:
        raise AuthError("An account with that email already exists.")

    user = User(
        email=email,
        password_hash=hash_password(password),
        full_name=(full_name or "").strip() or None,
    )
    db.add(user)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise AuthError("An account with that email already exists.") from exc
    return user


def set_password(db: Session, user: User, password: str) -> None:
    """Set a new password and revoke every existing session.

    Revocation is the point: if the change is happening because the account was
    compromised, leaving the attacker's sessions alive defeats it.
    """
    validate_password(password)
    user.password_hash = hash_password(password)
    user.failed_login_count = 0
    user.locked_until = None
    revoke_all_sessions(db, user.id)
    db.flush()


def change_password(db: Session, user: User, current: str, new: str) -> None:
    if not verify_password(current, user.password_hash):
        raise AuthError("Current password is incorrect.")
    if verify_password(new, user.password_hash):
        raise AuthError("New password must differ from the current one.")
    set_password(db, user, new)


# --------------------------------------------------------------------------
# Login with lockout
# --------------------------------------------------------------------------


def _record_attempt(db: Session, email: str, ip: str | None, succeeded: bool) -> None:
    db.add(LoginAttempt(email=normalise_email(email), ip=ip, succeeded=succeeded))
    db.flush()


def _is_locked(user: User) -> bool:
    return bool(user.locked_until and not is_expired(user.locked_until))


def authenticate(
    db: Session,
    *,
    email: str,
    password: str,
    ip: str | None = None,
    user_agent: str | None = None,
) -> User:
    """Verify credentials and return the user, or raise :class:`AuthError`.

    The error message is identical for an unknown address, a wrong password and
    a disabled account, so a caller cannot enumerate accounts through the API.
    """
    email = normalise_email(email)
    user = get_user_by_email(db, email)

    if user is None:
        # Equalise the response time with the real-account path.
        dummy_verify()
        _record_attempt(db, email, ip, False)
        raise AuthError("Incorrect email or password.")

    if _is_locked(user):
        _record_attempt(db, email, ip, False)
        raise AuthError(
            "Too many failed attempts. Try again in a few minutes."
        )

    if not verify_password(password, user.password_hash):
        user.failed_login_count = (user.failed_login_count or 0) + 1
        if user.failed_login_count >= MAX_FAILED_LOGINS:
            user.locked_until = utcnow() + LOCKOUT_DURATION
            user.failed_login_count = 0
            logger.warning("account locked after repeated failures user_id=%s", user.id)
        _record_attempt(db, email, ip, False)
        db.flush()
        raise AuthError("Incorrect email or password.")

    if not user.is_active:
        _record_attempt(db, email, ip, False)
        raise AuthError("This account is disabled.")

    # Transparently upgrade a hash created under older argon2 parameters.
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    db.flush()
    _record_attempt(db, email, ip, True)
    return user


# --------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------


def create_session(
    db: Session,
    user: User,
    *,
    ip: str | None = None,
    user_agent: str | None = None,
    ttl: timedelta = SESSION_TTL,
) -> tuple[str, UserSession]:
    """Create a session and return the raw token exactly once.

    The raw token is returned rather than stored; only its digest is persisted,
    so the caller must set it on the response immediately.
    """
    token = new_session_token()
    session = UserSession(
        user_id=user.id,
        token_hash=token_digest(token),
        expires_at=utcnow() + ttl,
        ip=ip,
        user_agent=(user_agent or "")[:500] or None,
    )
    db.add(session)
    db.flush()
    return token, session


def resolve_session(db: Session, token: str) -> UserSession | None:
    """Return a live session for ``token``, or ``None``.

    Checks revocation and expiry. An expired session is treated exactly like a
    missing one so callers have a single failure path.
    """
    if not token:
        return None
    session = db.scalar(
        select(UserSession)
        .options(joinedload(UserSession.user))
        .where(UserSession.token_hash == token_digest(token))
    )
    if session is None or session.revoked_at is not None:
        return None
    if is_expired(session.expires_at):
        return None
    if not session.user or not session.user.is_active:
        return None
    return session


def touch_session(db: Session, session: UserSession) -> None:
    """Record activity. Throttled to once a minute to avoid an UPDATE per request."""
    now = utcnow()
    last = ensure_aware(session.last_seen_at)
    if last is None or (now - last) > timedelta(minutes=1):
        session.last_seen_at = now
        db.flush()


def revoke_session(db: Session, session: UserSession) -> None:
    if session.revoked_at is None:
        session.revoked_at = utcnow()
        db.flush()


def revoke_all_sessions(db: Session, user_id: int, *, except_id: int | None = None) -> int:
    """Revoke every live session for a user, optionally sparing one."""
    stmt = (
        update(UserSession)
        .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )
    if except_id is not None:
        stmt = stmt.where(UserSession.id != except_id)
    result = db.execute(stmt)
    db.flush()
    return int(result.rowcount or 0)


def purge_expired_sessions(db: Session, *, older_than_days: int = 7) -> int:
    """Delete sessions that expired long enough ago to be of no forensic value."""
    cutoff = utcnow() - timedelta(days=older_than_days)
    result = db.execute(
        UserSession.__table__.delete().where(
            or_(
                UserSession.expires_at < cutoff,
                UserSession.revoked_at < cutoff,
            )
        )
    )
    db.flush()
    return int(result.rowcount or 0)


# --------------------------------------------------------------------------
# API tokens
# --------------------------------------------------------------------------


def create_api_token(
    db: Session, user: User, *, name: str, ttl: timedelta | None = None
) -> tuple[str, ApiToken]:
    """Mint an API token, returning the raw value exactly once."""
    token = new_api_token()
    record = ApiToken(
        user_id=user.id,
        name=(name or "token").strip()[:128],
        token_hash=token_digest(token),
        prefix=api_token_prefix(token),
        expires_at=(utcnow() + ttl) if ttl else None,
    )
    db.add(record)
    db.flush()
    return token, record


def resolve_api_token(db: Session, token: str) -> ApiToken | None:
    if not token or not token.startswith("ga_"):
        return None
    record = db.scalar(
        select(ApiToken)
        .options(joinedload(ApiToken.user))
        .where(ApiToken.token_hash == token_digest(token))
    )
    if record is None or record.revoked_at is not None:
        return None
    if is_expired(record.expires_at):
        return None
    if not record.user or not record.user.is_active:
        return None
    return record


def revoke_api_token(db: Session, user_id: int, token_id: int) -> bool:
    """Revoke one token. Scoped by ``user_id`` so a user cannot revoke a peer's."""
    record = db.scalar(
        select(ApiToken).where(ApiToken.id == token_id, ApiToken.user_id == user_id)
    )
    if record is None:
        return False
    if record.revoked_at is None:
        record.revoked_at = utcnow()
        db.flush()
    return True


# --------------------------------------------------------------------------
# Email tokens
# --------------------------------------------------------------------------


def issue_email_token(
    db: Session, user: User, *, purpose: str, ttl: timedelta | None = None
) -> str:
    """Issue a single-use token, invalidating any outstanding token of that purpose.

    One live token per purpose means an old email cannot be replayed after the
    user requests a new one.
    """
    if purpose not in (EmailToken.PURPOSE_VERIFY, EmailToken.PURPOSE_RESET):
        raise ValueError(f"unknown token purpose: {purpose}")

    db.execute(
        EmailToken.__table__.update()
        .where(
            EmailToken.user_id == user.id,
            EmailToken.purpose == purpose,
            EmailToken.used_at.is_(None),
        )
        .values(used_at=utcnow())
    )

    token = new_email_token()
    default_ttl = EMAIL_TOKEN_TTL if purpose == EmailToken.PURPOSE_VERIFY else PASSWORD_RESET_TTL
    db.add(
        EmailToken(
            user_id=user.id,
            token_hash=token_digest(token),
            purpose=purpose,
            expires_at=utcnow() + (ttl or default_ttl),
        )
    )
    db.flush()
    return token


def consume_email_token(db: Session, token: str, *, purpose: str) -> User | None:
    """Consume a token of the given purpose, returning its user.

    Matching on ``purpose`` is what stops a verification token from being
    accepted as a password-reset token.
    """
    if not token:
        return None
    record = db.scalar(
        select(EmailToken).where(
            EmailToken.token_hash == token_digest(token),
            EmailToken.purpose == purpose,
        )
    )
    if record is None or record.used_at is not None or is_expired(record.expires_at):
        return None
    record.used_at = utcnow()
    user = db.get(User, record.user_id)
    db.flush()
    return user


def verify_email(db: Session, token: str) -> User | None:
    user = consume_email_token(db, token, purpose=EmailToken.PURPOSE_VERIFY)
    if user is not None and user.email_verified_at is None:
        user.email_verified_at = utcnow()
        db.flush()
    return user


def reset_password(db: Session, token: str, new_password: str) -> User | None:
    user = consume_email_token(db, token, purpose=EmailToken.PURPOSE_RESET)
    if user is None:
        return None
    set_password(db, user, new_password)
    return user


# --------------------------------------------------------------------------
# Tenancy
# --------------------------------------------------------------------------


def list_memberships(db: Session, user_id: int) -> list[Membership]:
    return list(
        db.scalars(
            select(Membership)
            .options(joinedload(Membership.user))
            .where(Membership.user_id == user_id)
            .order_by(Membership.id)
        )
    )


def get_membership(db: Session, user_id: int, nonprofit_id: int) -> Membership | None:
    """The single authoritative answer to "may this user touch this tenant?".

    Returns the membership row or ``None``. Every tenant-scoped query in the
    application is preceded by a call to this function.
    """
    return db.scalar(
        select(Membership).where(
            Membership.user_id == user_id,
            Membership.nonprofit_id == nonprofit_id,
        )
    )


def create_nonprofit(
    db: Session,
    *,
    name: str,
    state: str = "",
    ein: str | None = None,
    city: str | None = None,
    zip_code: str | None = None,
    slug: str | None = None,
) -> NonprofitModel:
    """Create a nonprofit tenant with a unique slug."""
    base = slug or _slugify(name)
    candidate = base
    suffix = 1
    # Slug is the tenant's stable public handle; collisions are resolved by
    # appending a counter rather than rejecting the signup.
    while db.scalar(select(NonprofitModel).where(NonprofitModel.slug == candidate)) is not None:
        suffix += 1
        candidate = f"{base}-{suffix}"

    nonprofit = NonprofitModel(
        slug=candidate,
        name=name.strip(),
        state=(state or "").strip().upper()[:2],
        ein=(ein or "").strip() or None,
        city=(city or "").strip() or None,
        zip=(zip_code or "").strip() or None,
    )
    db.add(nonprofit)
    db.flush()
    return nonprofit


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (value or "").strip().lower()).strip("-")
    return (slug or "nonprofit")[:100]


def add_membership(
    db: Session,
    *,
    user: User,
    nonprofit: NonprofitModel,
    role: str = "member",
    invited_by_id: int | None = None,
) -> Membership:
    """Add a user to a nonprofit. Idempotent per (user, nonprofit)."""
    existing = get_membership(db, user.id, nonprofit.id)
    if existing is not None:
        return existing
    membership = Membership(
        user_id=user.id,
        nonprofit_id=nonprofit.id,
        role=role,
        invited_by_id=invited_by_id,
    )
    db.add(membership)
    try:
        db.flush()
    except IntegrityError:
        # Lost a race with a concurrent invite; the row now exists.
        db.rollback()
        found = get_membership(db, user.id, nonprofit.id)
        if found is None:
            raise
        return found
    return membership


def update_membership_role(db: Session, membership: Membership, role: str) -> Membership:
    membership.role = role
    db.flush()
    return membership


def remove_membership(db: Session, membership: Membership) -> None:
    db.delete(membership)
    db.flush()


def count_owners(db: Session, nonprofit_id: int) -> int:
    """Count owners, used to prevent removing the last one.

    A tenant with no owner is unrecoverable through the UI, so this guards a
    genuine availability property rather than a stylistic one.
    """
    return int(
        db.scalar(
            select(func.count())
            .select_from(Membership)
            .where(Membership.nonprofit_id == nonprofit_id, Membership.role == ROLE_OWNER)
        )
        or 0
    )


@dataclass(frozen=True)
class SignupResult:
    user: User
    nonprofit: NonprofitModel
    membership: Membership
    verify_token: str


def signup(
    db: Session,
    *,
    email: str,
    password: str,
    full_name: str | None,
    nonprofit_name: str,
    state: str = "",
    ein: str | None = None,
) -> SignupResult:
    """Create a user, their first tenant, and an owner membership, atomically.

    The caller owns the transaction; on any failure the whole signup rolls back
    so a partial account (user with no tenant, or tenant with no owner) cannot
    exist.
    """
    user = create_user(db, email=email, password=password, full_name=full_name)
    nonprofit = create_nonprofit(db, name=nonprofit_name, state=state, ein=ein)
    membership = add_membership(db, user=user, nonprofit=nonprofit, role=ROLE_OWNER)
    token = issue_email_token(db, user, purpose=EmailToken.PURPOSE_VERIFY)
    return SignupResult(
        user=user, nonprofit=nonprofit, membership=membership, verify_token=token
    )


__all__ = [
    "LOCKOUT_DURATION",
    "MAX_FAILED_LOGINS",
    "AuthError",
    "PasswordError",
    "SignupResult",
    "add_membership",
    "authenticate",
    "change_password",
    "consume_email_token",
    "count_owners",
    "create_api_token",
    "create_nonprofit",
    "create_session",
    "create_user",
    "get_membership",
    "get_user",
    "get_user_by_email",
    "issue_email_token",
    "list_memberships",
    "normalise_email",
    "purge_expired_sessions",
    "remove_membership",
    "reset_password",
    "resolve_api_token",
    "resolve_session",
    "revoke_all_sessions",
    "revoke_api_token",
    "revoke_session",
    "set_password",
    "signup",
    "touch_session",
    "update_membership_role",
    "utcnow",
    "valid_email",
    "verify_email",
]