"""Static frontend and the app shell.

The landing page is a self-contained artifact: React and Tailwind are inlined,
so it renders with no CDN, no bundler and no network at all. That matters for
two reasons - it works offline in a locked-down deployment, and there is no
third-party script that could change under us. It is served here rather than by
a separate web server so a single process can run the whole product.

The signed-in application is a small JavaScript app in ``app.js`` that talks to
the JSON API. It is served from the same origin as the API, which means the
session cookie is first-party and no cross-origin credential rules are needed.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError

from accounts.models import WaitlistEntry
from api import ratelimit
from hunter.config import get_settings

logger = logging.getLogger("frontend")

STATIC_DIR = Path(__file__).parent / "static"

router = APIRouter(tags=["frontend"])


class WaitlistIn(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    source: str | None = Field(default=None, max_length=64)


def _asset(name: str) -> Path:
    """Resolve a static asset, refusing anything that escapes the directory."""
    path = (STATIC_DIR / name).resolve()
    if not str(path).startswith(str(STATIC_DIR.resolve())):
        raise HTTPException(status_code=404, detail="Not found.")
    return path


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def landing() -> HTMLResponse:
    """The marketing page."""
    path = _asset("landing.html")
    if not path.is_file():
        raise HTTPException(status_code=500, detail="Landing page is missing.")
    return FileResponse(path, media_type="text/html; charset=utf-8")


@router.get("/app", response_class=HTMLResponse, include_in_schema=False)
def app_shell() -> HTMLResponse:
    """The signed-in application shell.

    A single HTML document; the JavaScript in ``app.js`` decides whether to
    render the sign-in screen or the dashboard based on ``/api/auth/me``. It
    holds no data itself, so serving it to an anonymous visitor discloses
    nothing.
    """
    path = _asset("app.html")
    if not path.is_file():
        raise HTTPException(status_code=500, detail="Application shell is missing.")
    return FileResponse(path, media_type="text/html; charset=utf-8")


@router.get("/app.js", include_in_schema=False)
def app_js() -> FileResponse:
    return FileResponse(_asset("app.js"), media_type="text/javascript; charset=utf-8")


@router.get("/styles.css", include_in_schema=False)
def styles_css() -> FileResponse:
    return FileResponse(_asset("styles.css"), media_type="text/css; charset=utf-8")


@router.get("/favicon.svg", include_in_schema=False)
def favicon() -> FileResponse:
    return FileResponse(_asset("favicon.svg"), media_type="image/svg+xml")


@router.get("/healthz", include_in_schema=False)
def healthz() -> dict[str, str]:
    """Liveness probe. Deliberately touches nothing, so it stays up when the
    database is down and a load balancer can still see the process."""
    return {"status": "ok"}


@router.post("/api/waitlist", status_code=202)
def join_waitlist(payload: WaitlistIn, request: Request) -> dict[str, str]:
    """Capture a lead from the marketing page.

    Answers 202 for every valid address, including one already on the list, so
    the endpoint cannot be used to check whether a competitor signed up.
    """
    from accounts.service import normalise_email, valid_email

    ip = ratelimit.client_ip(request)
    if get_settings().rate_limit_enabled and not ratelimit.SIGNUP_IP.allow(f"waitlist:{ip}"):
        raise HTTPException(status_code=429, detail="Too many requests.")

    email = normalise_email(payload.email)
    if not valid_email(email):
        raise HTTPException(status_code=422, detail="Enter a valid email address.")

    # The waitlist is the only unauthenticated write, so it opens its own short
    # session rather than taking the request-scoped dependency.
    from hunter.db import session_scope

    with session_scope() as db:
        db.add(
            WaitlistEntry(
                email=email,
                source=(payload.source or "landing")[:64],
                ip=ip,
            )
        )
        try:
            db.flush()
        except IntegrityError:
            # Already on the list. Same response as a fresh signup.
            db.rollback()

    return {"status": "accepted"}


__all__ = ["router"]