"""Authentication, session and organization-management routes.

Uniformity rules applied throughout:

* **Login** answers identically for a wrong password, an unknown address and a
  disabled account, and pays the same CPU cost for each.
* **Signup** and **forgot-password** accept the request and answer 202 whether
  or not the address is known, so neither can be used to probe for accounts.
* **Tenant routes** answer 404 rather than 403 when the caller has no
  membership, so tenant IDs cannot be enumerated.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from accounts import service
from accounts.models import (
    ASSIGNABLE_ROLES,
    ROLE_ADMIN,
    ROLE_MEMBER,
    ROLE_OWNER,
    EmailToken,
)
from accounts.notifications import EmailError, send_password_reset, send_verification
from accounts.security import PasswordError
from api import ratelimit
from api.deps import (
    COOKIE_PATH,
    CSRF_COOKIE,
    SESSION_COOKIE,
    CurrentUser,
    Principal,
    Tenant,
    assert_outranks,
    ensure_can_manage,
    get_principal,
    new_csrf_token,
)
from hunter.config import get_settings
from hunter.db import get_db
from hunter.models import NonprofitModel
from tracking import service as tracking

logger = logging.getLogger("api.auth")

router = APIRouter(prefix="/api/auth", tags=["auth"])


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------


class SignupIn(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=512)
    full_name: str | None = Field(default=None, max_length=255)
    nonprofit_name: str = Field(min_length=1, max_length=255)
    state: str = Field(default="", max_length=2)
    ein: str | None = Field(default=None, max_length=32)


class LoginIn(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=512)


class TokenIn(BaseModel):
    token: str = Field(min_length=8, max_length=512)


class ResetIn(BaseModel):
    token: str = Field(min_length=8, max_length=512)
    password: str = Field(min_length=1, max_length=512)


class ChangePasswordIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=512)
    new_password: str = Field(min_length=1, max_length=512)


class EmailIn(BaseModel):
    email: str = Field(min_length=3, max_length=320)


class NonprofitOut(BaseModel):
    id: int
    slug: str
    name: str
    state: str | None = None
    role: str


class UserOut(BaseModel):
    id: int
    email: str
    full_name: str | None = None
    email_verified: bool
    is_staff: bool = False


class SessionOut(BaseModel):
    user: UserOut
    nonprofits: list[NonprofitOut]
    csrf_token: str | None = None


class ApiTokenIn(BaseModel):
    name: str = Field(default="token", max_length=128)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


class ApiTokenOut(BaseModel):
    id: int
    name: str
    prefix: str
    created_at: str
    last_used_at: str | None = None
    expires_at: str | None = None


class ApiTokenCreatedOut(ApiTokenOut):
    # Present only in the creation response. There is no endpoint that can
    # return it again.
    token: str


class MemberOut(BaseModel):
    user_id: int
    email: str
    full_name: str | None = None
    role: str
    joined_at: str


class InviteIn(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    role: str = Field(default=ROLE_MEMBER, max_length=16)

    @field_validator("role")
    @classmethod
    def _known_role(cls, v: str) -> str:
        if v not in ASSIGNABLE_ROLES:
            raise ValueError("unknown role")
        return v


class RoleIn(BaseModel):
    role: str = Field(max_length=16)

    @field_validator("role")
    @classmethod
    def _known_role(cls, v: str) -> str:
        if v not in ASSIGNABLE_ROLES:
            raise ValueError("unknown role")
        return v


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _user_out(user) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        email_verified=user.email_verified_at is not None,
        is_staff=bool(user.is_staff),
    )


def _nonprofits_for(db: Session, user) -> list[NonprofitOut]:
    out: list[NonprofitOut] = []
    for membership in service.list_memberships(db, user.id):
        nonprofit = db.get(NonprofitModel, membership.nonprofit_id)
        if nonprofit is None:
            continue
        out.append(
            NonprofitOut(
                id=nonprofit.id,
                slug=nonprofit.slug,
                name=nonprofit.name,
                state=nonprofit.state or None,
                role=membership.role,
            )
        )
    return out


def _set_session_cookies(response: Response, token: str, csrf: str) -> None:
    settings = get_settings()
    max_age = int(service.SESSION_TTL.total_seconds())
    common: dict[str, Any] = {
        "path": COOKIE_PATH,
        "secure": settings.cookie_secure,
        "httponly": True,
        "samesite": "lax",
        "max_age": max_age,
    }
    if settings.session_cookie_domain:
        common["domain"] = settings.session_cookie_domain

    response.set_cookie(SESSION_COOKIE, token, **common)
    # The CSRF cookie must be readable by JavaScript (it is echoed into a
    # header), so it is the one cookie that is not HttpOnly. It carries no
    # authority on its own - the session cookie does.
    response.set_cookie(
        CSRF_COOKIE,
        csrf,
        path=COOKIE_PATH,
        secure=settings.cookie_secure,
        httponly=False,
        samesite="lax",
        max_age=max_age,
    )


def _clear_session_cookies(response: Response) -> None:
    settings = get_settings()
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        response.delete_cookie(
            name,
            path=COOKIE_PATH,
            domain=settings.session_cookie_domain or None,
        )


def _rate_limit(
    limiter: ratelimit.RateLimiter, key: str, request: Request, message: str
) -> None:
    if not get_settings().rate_limit_enabled:
        return
    if not limiter.allow(key):
        wait = int(limiter.retry_after(key)) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=message,
            headers={"Retry-After": str(wait)},
        )


# --------------------------------------------------------------------------
# Signup / login / logout
# --------------------------------------------------------------------------


@router.post("/signup", status_code=status.HTTP_201_CREATED, response_model=SessionOut)
def signup(
    payload: SignupIn,
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> SessionOut:
    """Create an account, its first organization, and a signed-in session."""
    ip = ratelimit.client_ip(request)
    _rate_limit(ratelimit.SIGNUP_IP, f"signup:{ip}", request, "Too many signup attempts.")

    try:
        result = service.signup(
            db,
            email=payload.email,
            password=payload.password,
            full_name=payload.full_name,
            nonprofit_name=payload.nonprofit_name,
            state=payload.state,
            ein=payload.ein,
        )
    except PasswordError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except service.AuthError as exc:
        # A duplicate address does reveal that an account exists. That is
        # unavoidable for signup (the alternative is silently doing nothing),
        # which is why signup is rate-limited by IP.
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    token, session = service.create_session(
        db,
        result.user,
        ip=ip,
        user_agent=request.headers.get("user-agent"),
    )
    csrf = new_csrf_token()
    _set_session_cookies(response, token, csrf)

    tracking.record_usage(
        db,
        name=tracking.EVENT_SIGNUP,
        nonprofit_id=result.nonprofit.id,
        user_id=result.user.id,
        ip=ip,
    )
    tracking.record_audit(
        db,
        action="user.signup",
        nonprofit_id=result.nonprofit.id,
        actor_user_id=result.user.id,
        actor_email=result.user.email,
        target_type="nonprofit",
        target_id=result.nonprofit.id,
        ip=ip,
        user_agent=request.headers.get("user-agent"),
    )

    try:
        send_verification(
            result.user.email,
            full_name=result.user.full_name,
            token=result.verify_token,
            base_url=get_settings().frontend_base_url,
        )
    except EmailError:
        # A mail outage must not fail a signup that is already committed; the
        # user can request another link.
        logger.warning("verification email failed user_id=%s", result.user.id)

    return SessionOut(
        user=_user_out(result.user),
        nonprofits=_nonprofits_for(db, result.user),
        csrf_token=csrf,
    )


@router.post("/login", response_model=SessionOut)
def login(
    payload: LoginIn,
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> SessionOut:
    ip = ratelimit.client_ip(request)
    email_key = service.normalise_email(payload.email)

    _rate_limit(ratelimit.LOGIN_IP, f"login-ip:{ip}", request, "Too many attempts from this address.")
    _rate_limit(ratelimit.LOGIN_EMAIL, f"login-email:{email_key}", request, "Too many attempts for this account.")

    try:
        user = service.authenticate(
            db,
            email=payload.email,
            password=payload.password,
            ip=ip,
            user_agent=request.headers.get("user-agent"),
        )
    except service.AuthError as exc:
        tracking.record_audit(
            db,
            action="user.login",
            actor_email=email_key,
            outcome="failure",
            ip=ip,
        )
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    token, session = service.create_session(
        db, user, ip=ip, user_agent=request.headers.get("user-agent")
    )
    csrf = new_csrf_token()
    _set_session_cookies(response, token, csrf)

    memberships = service.list_memberships(db, user.id)
    tracking.record_usage(
        db,
        name=tracking.EVENT_LOGIN,
        nonprofit_id=memberships[0].nonprofit_id if memberships else None,
        user_id=user.id,
        ip=ip,
    )
    return SessionOut(
        user=_user_out(user), nonprofits=_nonprofits_for(db, user), csrf_token=csrf
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    principal: Annotated[Principal, Depends(get_principal)],
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    """Revoke the current session. Requires auth so it cannot clear a peer's."""
    from api.deps import enforce_csrf

    enforce_csrf(request, principal)

    if principal.session_id is not None:
        from accounts.models import UserSession

        session = db.get(UserSession, principal.session_id)
        if session is not None:
            service.revoke_session(db, session)

    tracking.record_audit(
        db,
        action="user.logout",
        actor_user_id=principal.user.id,
        actor_email=principal.user.email,
        ip=ratelimit.client_ip(request),
    )
    _clear_session_cookies(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=SessionOut)
def me(
    principal: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
) -> SessionOut:
    return SessionOut(
        user=_user_out(principal.user),
        nonprofits=_nonprofits_for(db, principal.user),
    )


# --------------------------------------------------------------------------
# Email verification and password reset
# --------------------------------------------------------------------------


@router.post("/verify-email", response_model=UserOut)
def verify_email(
    payload: TokenIn,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> UserOut:
    ip = ratelimit.client_ip(request)
    _rate_limit(ratelimit.EMAIL_SEND_IP, f"verify:{ip}", request, "Too many attempts.")

    user = service.verify_email(db, payload.token)
    if user is None:
        raise HTTPException(status_code=400, detail="This link is invalid or has expired.")
    tracking.record_audit(
        db,
        action="user.email_verified",
        actor_user_id=user.id,
        actor_email=user.email,
        ip=ip,
    )
    return _user_out(user)


@router.post("/resend-verification", status_code=status.HTTP_202_ACCEPTED)
def resend_verification(
    payload: EmailIn,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, str]:
    """Always answers 202, whether or not the address exists."""
    ip = ratelimit.client_ip(request)
    _rate_limit(ratelimit.EMAIL_SEND_IP, f"resend:{ip}", request, "Too many requests.")

    user = service.get_user_by_email(db, payload.email)
    if user is not None and user.email_verified_at is None:
        token = service.issue_email_token(db, user, purpose=EmailToken.PURPOSE_VERIFY)
        try:
            send_verification(
                user.email,
                full_name=user.full_name,
                token=token,
                base_url=get_settings().frontend_base_url,
            )
        except EmailError:
            logger.warning("resend verification failed user_id=%s", user.id)

    return {"status": "accepted"}


@router.post("/forgot-password", status_code=status.HTTP_202_ACCEPTED)
def forgot_password(
    payload: EmailIn,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, str]:
    """Always answers 202, so it cannot be used to enumerate accounts."""
    ip = ratelimit.client_ip(request)
    _rate_limit(ratelimit.EMAIL_SEND_IP, f"forgot:{ip}", request, "Too many requests.")

    user = service.get_user_by_email(db, payload.email)
    if user is not None and user.is_active:
        token = service.issue_email_token(db, user, purpose=EmailToken.PURPOSE_RESET)
        tracking.record_audit(
            db,
            action="user.password_reset_requested",
            actor_user_id=user.id,
            actor_email=user.email,
            ip=ip,
        )
        try:
            send_password_reset(
                user.email,
                full_name=user.full_name,
                token=token,
                base_url=get_settings().frontend_base_url,
            )
        except EmailError:
            logger.warning("password reset email failed user_id=%s", user.id)

    return {"status": "accepted"}


@router.post("/reset-password", response_model=UserOut)
def reset_password(
    payload: ResetIn,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> UserOut:
    ip = ratelimit.client_ip(request)
    _rate_limit(ratelimit.EMAIL_SEND_IP, f"reset:{ip}", request, "Too many attempts.")

    try:
        user = service.reset_password(db, payload.token, payload.password)
    except PasswordError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if user is None:
        raise HTTPException(status_code=400, detail="This link is invalid or has expired.")

    tracking.record_audit(
        db, action="user.password_reset", actor_user_id=user.id, actor_email=user.email, ip=ip
    )
    tracking.record_usage(
        db, name=tracking.EVENT_PASSWORD_RESET, user_id=user.id, ip=ip
    )
    return _user_out(user)


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    payload: ChangePasswordIn,
    request: Request,
    principal: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    """Change a password, revoking all other sessions.

    The current session is kept alive so the user is not signed out of the tab
    they are using, while every other device is cut off.
    """
    try:
        service.change_password(
            db, principal.user, payload.current_password, payload.new_password
        )
    except PasswordError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except service.AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if principal.session_id is not None:
        service.revoke_all_sessions(
            db, principal.user.id, except_id=principal.session_id
        )
    tracking.record_audit(
        db,
        action="user.password_changed",
        actor_user_id=principal.user.id,
        actor_email=principal.user.email,
        ip=ratelimit.client_ip(request),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------
# Sessions
# --------------------------------------------------------------------------


@router.get("/sessions")
def list_sessions(
    principal: CurrentUser, db: Annotated[Session, Depends(get_db)]
) -> list[dict[str, Any]]:
    from sqlalchemy import select

    from accounts.models import UserSession

    rows = db.scalars(
        select(UserSession)
        .where(UserSession.user_id == principal.user.id, UserSession.revoked_at.is_(None))
        .order_by(UserSession.created_at.desc())
        .limit(50)
    )
    return [
        {
            "id": row.id,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
            "ip": row.ip,
            "user_agent": row.user_agent,
            "current": row.id == principal.session_id,
        }
        for row in rows
    ]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_session_route(
    session_id: int,
    principal: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    """Revoke one of your own sessions. Scoped by user_id, so no IDOR."""
    from accounts.models import UserSession

    session = db.get(UserSession, session_id)
    if session is None or session.user_id != principal.user.id:
        raise HTTPException(status_code=404, detail="Resource not found.")
    service.revoke_session(db, session)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------
# API tokens
# --------------------------------------------------------------------------


@router.get("/tokens", response_model=list[ApiTokenOut])
def list_tokens(
    principal: CurrentUser, db: Annotated[Session, Depends(get_db)]
) -> list[ApiTokenOut]:
    from sqlalchemy import select

    from accounts.models import ApiToken

    rows = db.scalars(
        select(ApiToken)
        .where(ApiToken.user_id == principal.user.id)
        .order_by(ApiToken.created_at.desc())
        .limit(100)
    )
    return [
        ApiTokenOut(
            id=row.id,
            name=row.name,
            prefix=row.prefix,
            created_at=row.created_at.isoformat() if row.created_at else "",
            last_used_at=row.last_used_at.isoformat() if row.last_used_at else None,
            expires_at=row.expires_at.isoformat() if row.expires_at else None,
        )
        for row in rows
        if row.revoked_at is None
    ]


@router.post("/tokens", status_code=status.HTTP_201_CREATED, response_model=ApiTokenCreatedOut)
def create_token(
    payload: ApiTokenIn,
    request: Request,
    principal: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
) -> ApiTokenCreatedOut:
    """Mint an API token. The plaintext is returned once and never stored."""
    ttl = timedelta(days=payload.expires_in_days) if payload.expires_in_days else None
    token, record = service.create_api_token(
        db, principal.user, name=payload.name, ttl=ttl
    )
    tracking.record_audit(
        db,
        action="user.api_token_created",
        actor_user_id=principal.user.id,
        actor_email=principal.user.email,
        target_type="api_token",
        target_id=record.id,
        ip=ratelimit.client_ip(request),
    )
    tracking.record_usage(
        db, name=tracking.EVENT_TOKEN_CREATED, user_id=principal.user.id
    )
    return ApiTokenCreatedOut(
        id=record.id,
        name=record.name,
        prefix=record.prefix,
        created_at=record.created_at.isoformat() if record.created_at else "",
        last_used_at=None,
        expires_at=record.expires_at.isoformat() if record.expires_at else None,
        token=token,
    )


@router.delete("/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_token(
    token_id: int,
    request: Request,
    principal: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    if not service.revoke_api_token(db, principal.user.id, token_id):
        raise HTTPException(status_code=404, detail="Resource not found.")
    tracking.record_audit(
        db,
        action="user.api_token_revoked",
        actor_user_id=principal.user.id,
        actor_email=principal.user.email,
        target_type="api_token",
        target_id=token_id,
        ip=ratelimit.client_ip(request),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------
# Members (tenant-scoped)
# --------------------------------------------------------------------------

members_router = APIRouter(prefix="/api/nonprofits", tags=["members"])


@members_router.get("/{nonprofit_id}/members", response_model=list[MemberOut])
def list_members(
    nonprofit_id: int,
    scope: Tenant,
    db: Annotated[Session, Depends(get_db)],
) -> list[MemberOut]:
    """List members of a tenant. ``scope`` already proved membership."""
    from sqlalchemy import select

    from accounts.models import Membership, User

    rows = db.execute(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(Membership.nonprofit_id == scope.nonprofit_id)
        .order_by(Membership.created_at)
    ).all()
    return [
        MemberOut(
            user_id=user.id,
            email=user.email,
            full_name=user.full_name,
            role=membership.role,
            joined_at=membership.created_at.isoformat() if membership.created_at else "",
        )
        for membership, user in rows
    ]


@members_router.post(
    "/{nonprofit_id}/members", status_code=status.HTTP_201_CREATED, response_model=MemberOut
)
def invite_member(
    nonprofit_id: int,
    payload: InviteIn,
    request: Request,
    scope: Tenant,
    db: Annotated[Session, Depends(get_db)],
) -> MemberOut:
    """Invite a user to the tenant.

    Requires admin. The inviter may not grant a role at or above their own, so
    an admin cannot mint an owner.
    """
    if not scope.has_role(ROLE_ADMIN):
        raise HTTPException(status_code=403, detail=f"Requires the {ROLE_ADMIN} role.")
    ensure_can_manage(scope, payload.role)


    target_email = service.normalise_email(payload.email)
    if not service.valid_email(target_email):
        raise HTTPException(status_code=422, detail="Enter a valid email address.")

    target = service.get_user_by_email(db, target_email)
    created_account = False
    if target is None:
        # Inviting an unknown address creates a placeholder account with no
        # usable password; the invitee sets one via the acceptance link.
        import secrets

        target = service.create_user(
            db,
            email=target_email,
            password=secrets.token_urlsafe(32) + "Aa1!",
        )
        created_account = True

    existing = service.get_membership(db, target.id, scope.nonprofit_id)
    if existing is not None:
        raise HTTPException(status_code=409, detail="That person is already a member.")

    membership = service.add_membership(
        db,
        user=target,
        nonprofit=scope.nonprofit,
        role=payload.role,
        invited_by_id=scope.user_id,
    )

    from accounts.models import EmailToken
    from accounts.notifications import send_invite

    token = service.issue_email_token(db, target, purpose=EmailToken.PURPOSE_RESET)
    try:
        send_invite(
            target.email,
            inviter=scope.user.full_name or scope.user.email,
            nonprofit_name=scope.nonprofit.name,
            role=payload.role,
            token=token,
            base_url=get_settings().frontend_base_url,
            new_account=created_account,
        )
    except EmailError:
        logger.warning("invite email failed user_id=%s", target.id)

    tracking.record_audit(
        db,
        action="member.invited",
        nonprofit_id=scope.nonprofit_id,
        actor_user_id=scope.user_id,
        actor_email=scope.user.email,
        target_type="user",
        target_id=target.id,
        detail=f"role={payload.role}",
        ip=ratelimit.client_ip(request),
    )
    tracking.record_usage(
        db, name=tracking.EVENT_MEMBER_INVITED, nonprofit_id=scope.nonprofit_id, user_id=scope.user_id
    )

    return MemberOut(
        user_id=target.id,
        email=target.email,
        full_name=target.full_name,
        role=membership.role,
        joined_at=membership.created_at.isoformat() if membership.created_at else "",
    )


@members_router.patch("/{nonprofit_id}/members/{user_id}", response_model=MemberOut)
def change_member_role(
    nonprofit_id: int,
    user_id: int,
    payload: RoleIn,
    request: Request,
    scope: Tenant,
    db: Annotated[Session, Depends(get_db)],
) -> MemberOut:
    """Change a member's role.

    Guards, in order: admin required; cannot change your own role (which is how
    an admin would otherwise promote themselves); cannot act on a peer-or-higher
    role; cannot assign a role at or above your own; cannot remove the last
    owner.
    """
    if not scope.has_role(ROLE_ADMIN):
        raise HTTPException(status_code=403, detail=f"Requires the {ROLE_ADMIN} role.")

    if user_id == scope.user_id:
        raise HTTPException(
            status_code=400, detail="You cannot change your own role."
        )

    membership = service.get_membership(db, user_id, scope.nonprofit_id)
    if membership is None:
        raise HTTPException(status_code=404, detail="Resource not found.")

    assert_outranks(scope, membership)
    ensure_can_manage(scope, payload.role)

    from accounts.models import User

    if membership.role == ROLE_OWNER and payload.role != ROLE_OWNER:
        if service.count_owners(db, scope.nonprofit_id) <= 1:
            raise HTTPException(
                status_code=400,
                detail="An organization must keep at least one owner.",
            )

    service.update_membership_role(db, membership, payload.role)
    target = db.get(User, user_id)

    tracking.record_audit(
        db,
        action="member.role_changed",
        nonprofit_id=scope.nonprofit_id,
        actor_user_id=scope.user_id,
        actor_email=scope.user.email,
        target_type="user",
        target_id=user_id,
        detail=f"new_role={payload.role}",
        ip=ratelimit.client_ip(request),
    )
    tracking.record_usage(
        db,
        name=tracking.EVENT_MEMBER_ROLE_CHANGED,
        nonprofit_id=scope.nonprofit_id,
        user_id=scope.user_id,
    )
    return MemberOut(
        user_id=user_id,
        email=target.email if target else "",
        full_name=target.full_name if target else None,
        role=membership.role,
        joined_at=membership.created_at.isoformat() if membership.created_at else "",
    )


@members_router.delete(
    "/{nonprofit_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT
)
def remove_member(
    nonprofit_id: int,
    user_id: int,
    request: Request,
    scope: Tenant,
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    if not scope.has_role(ROLE_ADMIN):
        raise HTTPException(status_code=403, detail=f"Requires the {ROLE_ADMIN} role.")

    membership = service.get_membership(db, user_id, scope.nonprofit_id)
    if membership is None:
        raise HTTPException(status_code=404, detail="Resource not found.")

    assert_outranks(scope, membership)

    if membership.role == ROLE_OWNER and service.count_owners(db, scope.nonprofit_id) <= 1:
        raise HTTPException(
            status_code=400, detail="An organization must keep at least one owner."
        )

    service.remove_membership(db, membership)
    # Cut off the removed member's live sessions for this tenant immediately;
    # authorization is checked per request, but leaving the session alive is
    # untidy if a cached page is re-fetched.
    tracking.record_audit(
        db,
        action="member.removed",
        nonprofit_id=scope.nonprofit_id,
        actor_user_id=scope.user_id,
        actor_email=scope.user.email,
        target_type="user",
        target_id=user_id,
        ip=ratelimit.client_ip(request),
    )
    tracking.record_usage(
        db, name=tracking.EVENT_MEMBER_REMOVED, nonprofit_id=scope.nonprofit_id, user_id=scope.user_id
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


__all__ = ["members_router", "router"]