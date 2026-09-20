"""Request-time authentication and the tenancy boundary.

The central idea: a route never receives a bare ``nonprofit_id``. It receives a
:class:`TenantScope`, which can only be constructed by resolving a real
:class:`Membership` row for the authenticated user. A handler that forgets to
check tenancy cannot be written, because there is no ``nonprofit_id`` in scope
to forget about - it is reachable only through the object that already proved
access.

Tenant context is taken from the URL path, not from a client-supplied header or
body field. A path segment is visible in logs and access records, and it makes
the authorisation decision auditable after the fact.

CSRF: browser sessions ride in a cookie, which the browser attaches ambiently,
so state-changing requests additionally require a double-submit token. Bearer
API tokens are not ambient - the browser does not attach them automatically -
so they are exempt from CSRF, which is why the two mechanisms coexist.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from accounts import service
from accounts.models import (
    ROLE_ADMIN,
    ROLE_MEMBER,
    ROLE_OWNER,
    ROLE_VIEWER,
    Membership,
    User,
    outranks,
    rank,
)
from accounts.security import tokens_equal, utcnow
from hunter.db import get_db
from hunter.models import NonprofitModel

logger = logging.getLogger("api.auth")

SESSION_COOKIE = "ga_session"
CSRF_COOKIE = "ga_csrf"
CSRF_HEADER = "x-csrf-token"

# Conservative cookie flags. HttpOnly hides the session token from JavaScript so
# an XSS bug cannot exfiltrate it; SameSite=Lax blocks cross-site POSTs; Secure
# is set from configuration because local development is plain HTTP.
COOKIE_PATH = "/"


# Deliberately the *same callable* the routers depend on, not a wrapper.
#
# FastAPI keys its dependency cache on the callable object, so a wrapper
# function - even one that delegates - is a different key and yields a second
# session. Two open transactions per request deadlock on SQLite (the auth
# layer's writes take the database-wide write lock before the route body
# inserts) and waste a connection on PostgreSQL. Aliasing keeps one session.
_get_db_session = get_db


@dataclass(frozen=True)
class Principal:
    """An authenticated actor, independent of any tenant."""

    user: User
    via: str  # "session" | "api_token"
    session_id: int | None = None
    token_id: int | None = None


@dataclass(frozen=True)
class TenantScope:
    """Proof that ``principal.user`` may act within ``nonprofit``.

    Constructed only by :func:`get_tenant_scope`, which looks up the membership
    row. Holding one of these is the authorisation.
    """

    principal: Principal
    nonprofit: NonprofitModel
    membership: Membership

    @property
    def user(self) -> User:
        return self.principal.user

    @property
    def nonprofit_id(self) -> int:
        return self.nonprofit.id

    @property
    def user_id(self) -> int:
        return self.principal.user.id

    @property
    def role(self) -> str:
        return self.membership.role

    def has_role(self, minimum: str) -> bool:
        return rank(self.membership.role) >= rank(minimum)


def _extract_bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def get_principal(
    request: Request,
    db: Annotated[Session, Depends(_get_db_session)],
    authorization: Annotated[str | None, Header()] = None,
) -> Principal:
    """Resolve the caller from an API token or a session cookie.

    A malformed or expired credential raises 401 with a ``WWW-Authenticate``
    challenge rather than falling through to an anonymous identity, so a client
    can tell "not logged in" apart from "forbidden".
    """
    token = _extract_bearer(authorization)
    if token:
        record = service.resolve_api_token(db, token)
        if record is None:
            raise _unauthorized("Invalid or expired API token.")
        record.last_used_at = utcnow()
        db.flush()
        return Principal(user=record.user, via="api_token", token_id=record.id)

    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        session = service.resolve_session(db, cookie)
        if session is None:
            raise _unauthorized("Session expired. Sign in again.")
        service.touch_session(db, session)
        return Principal(user=session.user, via="session", session_id=session.id)

    raise _unauthorized("Authentication required.")


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


# --------------------------------------------------------------------------
# CSRF
# --------------------------------------------------------------------------

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def enforce_csrf(request: Request, principal: Principal) -> None:
    """Double-submit check for cookie-authenticated state changes.

    The token must appear in both a readable cookie and a request header. An
    attacker on another origin can cause the cookie to be sent but cannot read
    it to populate the header, and cannot set a custom header cross-origin
    without a successful CORS preflight.

    Bearer tokens are skipped: they are not attached automatically by the
    browser, so a cross-origin form cannot authenticate with them in the first
    place.
    """
    if principal.via != "session":
        return
    if request.method.upper() not in UNSAFE_METHODS:
        return

    cookie = request.cookies.get(CSRF_COOKIE)
    header = request.headers.get(CSRF_HEADER)
    if not cookie or not header or not tokens_equal(cookie, header):
        logger.warning("csrf rejected path=%s", request.url.path)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF validation failed.",
        )


def require_user(
    request: Request,
    principal: Annotated[Principal, Depends(get_principal)],
) -> Principal:
    """Authenticated principal, with CSRF enforced on unsafe methods."""
    enforce_csrf(request, principal)
    return principal


CurrentUser = Annotated[Principal, Depends(require_user)]


def require_verified_user(principal: CurrentUser) -> Principal:
    """Like :func:`require_user`, but demands a confirmed email address.

    Applied to actions that can spend money or send mail to third parties, so
    an unverified address cannot be used to reach them.
    """
    if principal.user.email_verified_at is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Confirm your email address to continue.",
        )
    return principal


VerifiedUser = Annotated[Principal, Depends(require_verified_user)]


# --------------------------------------------------------------------------
# Tenant resolution
# --------------------------------------------------------------------------


def get_tenant_scope(
    nonprofit_id: int,
    db: Annotated[Session, Depends(_get_db_session)],
    principal: CurrentUser,
) -> TenantScope:
    """Resolve ``nonprofit_id`` to a scope, or 404.

    A missing membership answers **404, not 403**. Returning 403 for an
    existing tenant and 404 for a missing one would let an attacker enumerate
    which nonprofit IDs exist - a common way to confirm a target is a customer.
    The response is deliberately identical in both cases.
    """
    nonprofit = db.get(NonprofitModel, nonprofit_id)
    if nonprofit is None:
        raise _not_found()

    membership = service.get_membership(db, principal.user.id, nonprofit_id)
    if membership is None:
        # Log internally; the response stays ambiguous.
        logger.warning(
            "tenant access denied user_id=%s nonprofit_id=%s",
            principal.user.id,
            nonprofit_id,
        )
        raise _not_found()

    return TenantScope(principal=principal, nonprofit=nonprofit, membership=membership)


def _not_found() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found."
    )


Tenant = Annotated[TenantScope, Depends(get_tenant_scope)]


def require_role(minimum: str) -> Callable[[TenantScope], TenantScope]:
    """Dependency factory enforcing a minimum role within the tenant.

    Usage::

        @router.post("/{nonprofit_id}/members", dependencies=[Depends(require_role(ROLE_ADMIN))])
    """

    def _checker(scope: Tenant) -> TenantScope:
        if not scope.has_role(minimum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires the {minimum} role.",
            )
        return scope

    return _checker


def ensure_can_manage(scope: TenantScope, target_role: str | None = None) -> None:
    """Guard a membership mutation against privilege escalation.

    Two rules, both of which matter:

    * A caller may only act on a target of strictly lower rank, so two admins
      cannot demote each other and an admin cannot touch an owner.
    * A caller may not grant a role at or above their own, so an admin cannot
      promote themselves or a colleague to owner.
    """
    if target_role is not None and rank(target_role) >= rank(scope.role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot assign a role at or above your own.",
        )


def assert_outranks(scope: TenantScope, target: Membership) -> None:
    if target.user_id == scope.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot modify your own membership this way.",
        )
    if not outranks(scope.role, target.role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot modify a member at or above your role.",
        )


__all__ = [
    "COOKIE_PATH",
    "CSRF_COOKIE",
    "CSRF_HEADER",
    "ROLE_ADMIN",
    "ROLE_MEMBER",
    "ROLE_OWNER",
    "ROLE_VIEWER",
    "SESSION_COOKIE",
    "CurrentUser",
    "Principal",
    "Tenant",
    "TenantScope",
    "VerifiedUser",
    "assert_outranks",
    "enforce_csrf",
    "ensure_can_manage",
    "get_principal",
    "get_tenant_scope",
    "new_csrf_token",
    "require_role",
    "require_user",
    "require_verified_user",
]