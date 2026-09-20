"""FastAPI application factory and shared dependencies."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from hunter.config import get_settings
from hunter.db import get_db, get_engine, init_db

logger = logging.getLogger("api")


def _cors_origins() -> list[str]:
    return get_settings().cors_origin_list


@asynccontextmanager
async def lifespan(app: FastAPI):
    if get_settings().database_url:
        try:
            init_db()
            logger.info("api: database schema ready")
        except Exception as exc:  # pragma: no cover - depends on environment
            # Do not crash the process: /api/health should still answer so a
            # load balancer can report the real problem.
            logger.error("api: database init failed: %s", type(exc).__name__)
    else:
        logger.warning("api: DATABASE_URL unset; database-backed routes will fail")
    yield


# Paths that may be framed. Everything else gets X-Frame-Options: DENY, because
# a grant tool has no business being embedded in someone else's page - that is
# the precondition for clickjacking a review decision.
_FRAMEABLE_PATHS = ("/healthz",)


def _security_headers(response, request: Request) -> None:
    """Apply baseline security headers to every response."""
    path = request.url.path
    if path not in _FRAMEABLE_PATHS:
        response.headers["X-Frame-Options"] = "DENY"

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"

    # The API serves JSON; it needs no scripts, frames or plugins, so the
    # policy is closed rather than permissive.
    if path.startswith("/api/"):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        )


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Granted Agent API",
        version="1.0.0",
        description="Grant Intelligence for all of America.",
        lifespan=lifespan,
        # Interactive docs are useful in development and an unnecessary map of
        # the attack surface in production, so they are gated on environment.
        docs_url="/api/docs" if settings.environment != "production" else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if settings.environment != "production" else None,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
        max_age=600,
    )

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        """Host-header validation plus security headers.

        The Host header is attacker-influenced. Rejecting unknown hosts blocks
        host-header injection classes (cache poisoning, password-reset link
        rewriting) before any handler runs.
        """
        allowed = settings.allowed_host_list
        host = (request.headers.get("host") or "").split(":")[0].lower()
        if host and host not in allowed:
            logger.warning("rejected unknown host header: %s", host)
            return JSONResponse({"detail": "Invalid host."}, status_code=400)

        response = await call_next(request)
        _security_headers(response, request)
        return response

    from api import auth as auth_routes
    from api import billing as billing_routes
    from api import grants as grants_routes
    from api import inner_court as inner_court_routes
    from api import tracking as tracking_routes
    from frontend.routes import router as frontend_router

    app.include_router(auth_routes.router)
    app.include_router(auth_routes.members_router)
    app.include_router(billing_routes.router)
    app.include_router(billing_routes.webhook_router)
    app.include_router(grants_routes.router)
    app.include_router(inner_court_routes.router)
    app.include_router(tracking_routes.router)
    app.include_router(frontend_router)

    @app.get("/api/health", tags=["meta"])
    def health() -> dict[str, object]:
        """Liveness, plus whether the database is actually reachable."""
        db_ok = False
        try:
            engine = get_engine()
            with engine.connect() as conn:
                conn.exec_driver_sql("SELECT 1")
            db_ok = True
        except Exception:
            db_ok = False
        return {"status": "ok" if db_ok else "degraded", "database": db_ok}

    return app


app = create_app()

__all__ = ["app", "create_app", "get_db"]