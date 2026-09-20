"""Engine / session plumbing for the Hunter."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from hunter.config import get_settings, reload_settings

_engine: Engine | None = None
_Session: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        url = get_settings().database_url
        kwargs: dict = {"pool_pre_ping": True, "future": True}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
            if ":memory:" not in url:
                # File-backed SQLite takes a database-wide write lock, and the
                # default wait is 5 seconds. A slow request that holds the
                # write lock while another one commits then fails outright with
                # "database is locked". 30 seconds is short enough to still
                # surface a genuine deadlock and long enough to ride out
                # ordinary contention. Production runs PostgreSQL and never
                # takes this branch.
                kwargs["connect_args"]["timeout"] = 30
        _engine = create_engine(url, **kwargs)
    return _engine


def get_sessionmaker() -> sessionmaker[Session]:
    global _Session
    if _Session is None:
        _Session = sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)
    return _Session


@contextmanager
def session_scope() -> Iterator[Session]:
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Create extensions and tables. Idempotent."""
    from sqlalchemy import text

    from hunter.models import Base

    engine = get_engine()
    with engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
    Base.metadata.create_all(engine)


def reset_engine() -> None:
    """Drop cached engine/sessionmaker (used by tests and the CLI).

    Also clears the settings cache: the engine is derived from
    ``settings.database_url``, so invalidating one without the other would let a
    caller change ``DATABASE_URL`` and still get an engine bound to the old
    database.
    """
    global _engine, _Session
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _Session = None
    reload_settings()


def get_db() -> Iterator[Session]:
    """The canonical per-request session dependency. Commits on success.

    This must be the *single* session dependency for the whole application.
    FastAPI caches a dependency by the identity of the callable, so two
    functions that both open a session (even if one wraps the other) produce two
    sessions per request. On SQLite that is fatal: the first session's writes
    hold the database-wide write lock and the second one fails with "database is
    locked" the moment it tries to insert. Keeping this in one place, imported
    by every router and by the auth layer, keeps the request to one transaction.
    """
    with session_scope() as session:
        yield session