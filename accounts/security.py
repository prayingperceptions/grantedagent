"""Password hashing, token minting and constant-time comparison.

Security decisions worth stating explicitly, because each one is load-bearing:

* Passwords use **argon2id** (memory-hard) rather than a fast hash. Argon2 is
  the current OWASP recommendation and resists GPU cracking in a way
  PBKDF2/bcrypt do not.
* Session and API tokens are **opaque random strings, stored only as a SHA-256
  digest**. A fast digest is correct here: unlike a password, the token is 256
  bits of CSPRNG output, so there is no dictionary to attack and no reason to
  pay argon2's cost on every authenticated request. Storing only the digest
  means a database dump does not hand an attacker live sessions.
* Comparisons use :func:`hmac.compare_digest` so verification time does not
  reveal how many leading characters matched.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Final

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from argon2.low_level import Type

# OWASP-recommended argon2id parameters: 19 MiB memory, 2 iterations, 1 lane.
_hasher: Final = PasswordHasher(
    time_cost=2,
    memory_cost=19 * 1024,
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)

SESSION_TOKEN_BYTES: Final = 32
API_TOKEN_BYTES: Final = 32
EMAIL_TOKEN_BYTES: Final = 32

# A prefix makes a leaked string identifiable as a credential, so secret
# scanners and revocation tooling can recognise it.
API_TOKEN_PREFIX: Final = "ga_"

SESSION_TTL: Final = timedelta(days=30)
EMAIL_TOKEN_TTL: Final = timedelta(hours=24)
PASSWORD_RESET_TTL: Final = timedelta(hours=2)

MIN_PASSWORD_LENGTH: Final = 12
MAX_PASSWORD_LENGTH: Final = 256


class PasswordError(ValueError):
    """Raised when a password fails policy. Message is safe to return."""


def hash_password(password: str) -> str:
    """Hash a plaintext password with argon2id."""
    return _hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against its argon2id hash.

    Returns ``False`` for a malformed hash rather than raising: a corrupt
    stored hash must not turn a failed login into a 500 that confirms the
    account exists.
    """
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True when a stored hash predates the current argon2 parameters."""
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except (InvalidHashError, ValueError):
        return True


# --------------------------------------------------------------------------
# Tokens
# --------------------------------------------------------------------------


def _new_token(nbytes: int, prefix: str = "") -> str:
    return prefix + secrets.token_urlsafe(nbytes)


def new_session_token() -> str:
    return _new_token(SESSION_TOKEN_BYTES)


def new_api_token() -> str:
    """A new API token. Shown to the user exactly once, never recoverable."""
    return _new_token(API_TOKEN_BYTES, API_TOKEN_PREFIX)


def new_email_token() -> str:
    return _new_token(EMAIL_TOKEN_BYTES)


def token_digest(token: str) -> str:
    """SHA-256 hex digest of a token, for storage and lookup.

    Deterministic so a token can be found by digest in one indexed query, and
    one-way so the digest is useless to an attacker who reads it.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_equal(a: str, b: str) -> bool:
    """Constant-time string comparison."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def api_token_prefix(token: str) -> str:
    """Leading characters of a token, safe to display in a token list.

    Enough to tell two tokens apart, not enough to reconstruct either.
    """
    return token[: len(API_TOKEN_PREFIX) + 8]


def utcnow() -> datetime:
    return datetime.now(UTC)


def ensure_aware(value: datetime | None) -> datetime | None:
    """Attach UTC to a naive datetime.

    Some drivers return naive datetimes even for a ``DateTime(timezone=True)``
    column. Comparing a naive value to an aware one raises ``TypeError`` in
    Python 3, so normalise at the boundary.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def is_expired(expires_at: datetime | None, *, now: datetime | None = None) -> bool:
    if expires_at is None:
        return False
    expires_at = ensure_aware(expires_at)
    return expires_at <= (now or utcnow())


# --------------------------------------------------------------------------
# Password policy
# --------------------------------------------------------------------------

# First-entry deny-list from public credential dumps. A complete check belongs
# against a breached-password corpus (Have I Been Pwned's k-anonymity range
# API), which needs a network call on the signup path; this is a cheap floor,
# not the primary control.
_COMMON_PASSWORDS: Final = frozenset(
    {
        "password", "password1", "password123", "12345678", "123456789",
        "1234567890", "qwerty123", "qwertyuiop", "letmein", "welcome",
        "admin", "administrator", "iloveyou", "monkey", "dragon",
        "football", "baseball", "sunshine", "princess", "trustno1",
        "abc123", "passw0rd", "p@ssw0rd", "changeme", "secret",
        "grantedagent", "qwerty1", "1q2w3e4r",
    }
)


def validate_password(password: str) -> None:
    """Enforce password policy, raising :class:`PasswordError` on failure.

    Length dominates password strength, so the policy favours a long minimum
    over character-class rules. The upper bound exists because argon2 cost
    scales with input size, making an unbounded password a cheap way to burn
    server CPU; 256 is far above any human-chosen secret.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordError(
            f"Password must be at most {MAX_PASSWORD_LENGTH} characters."
        )
    if password.lower() in _COMMON_PASSWORDS:
        raise PasswordError("That password is too common. Choose another.")
    if password.isdigit() or password.isalpha():
        raise PasswordError("Password must mix letters, numbers or symbols.")


# A fixed hash so the failed-login path costs the same as the success path.
# Without it, "no such user" returns immediately while a real account pays
# argon2's ~50ms, leaking account existence through response timing.
_DUMMY_HASH: Final = hash_password("not-a-real-password-timing-equaliser")


def dummy_verify() -> None:
    """Burn the CPU a real password check would, then discard the result.

    Called when the email is unknown so login timing does not reveal whether an
    account exists.
    """
    verify_password("timing-equaliser", _DUMMY_HASH)


__all__ = [
    "API_TOKEN_PREFIX",
    "EMAIL_TOKEN_TTL",
    "MAX_PASSWORD_LENGTH",
    "MIN_PASSWORD_LENGTH",
    "PASSWORD_RESET_TTL",
    "SESSION_TTL",
    "PasswordError",
    "api_token_prefix",
    "dummy_verify",
    "ensure_aware",
    "hash_password",
    "is_expired",
    "needs_rehash",
    "new_api_token",
    "new_email_token",
    "new_session_token",
    "token_digest",
    "tokens_equal",
    "utcnow",
    "validate_password",
    "verify_password",
]