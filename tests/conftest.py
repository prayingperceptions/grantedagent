"""Shared pytest fixtures.

Live-network tests are marked ``network`` and run by default (the acceptance
criteria require real federal/foundation data). Unit tests never touch the
network and use the HTML/feed fixtures in tests/fixtures.

The API fixtures live here rather than in a single test module so every suite
that needs an authenticated client - the API tests and the security tests -
shares one definition. A second copy would drift, and the security suite
depends on these fixtures being exactly what production runs.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from hunter.config import reload_settings

FIXTURES = Path(__file__).parent / "fixtures"

# A deterministic 32-byte vault key for tests. Not a secret: it exists only
# inside the test process and guards throwaway databases.
TEST_VAULT_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    """Settings are lru_cached; env changes in a test must take effect."""
    reload_settings()
    yield
    reload_settings()


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """An app wired to a throwaway SQLite database, for tests that need the API.

    The assertion below is deliberate: these tests create and delete rows, and an
    earlier version of this file silently wrote fixtures into a live Postgres
    because the settings cache outlived the engine reset. Fail loudly rather than
    ever mutate a real database.
    """
    from fastapi.testclient import TestClient

    from hunter import db as hunter_db

    db_path = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("CURRENT_NONPROFIT_ID", "")
    monkeypatch.setenv("INNER_COURT_KEY", TEST_VAULT_KEY)
    # Rate limiting off by default so tests are not order-dependent; the
    # dedicated rate-limit tests turn it back on explicitly.
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://testserver")
    monkeypatch.setenv("FRONTEND_BASE_URL", "http://testserver")

    hunter_db.reset_engine()
    # Import the SaaS models before creating tables so create_all knows about
    # them; the app imports them transitively, but this keeps the fixture
    # self-contained.
    import accounts.models  # noqa: F401
    import billing.models  # noqa: F401
    import tracking.models  # noqa: F401

    hunter_db.init_db()

    resolved = str(hunter_db.get_engine().url)
    assert resolved.startswith("sqlite"), f"refusing to run tests against {resolved}"

    from api.main import create_app

    with TestClient(create_app()) as c:
        yield c
    hunter_db.reset_engine()


@pytest.fixture()
def owner(client):
    """A signed-in account with its own tenant."""
    from tests.saas_helpers import signup

    return signup(client, nonprofit_name="Milwaukee Families Coalition", state="WI")


def pytest_addoption(parser):
    parser.addoption(
        "--no-network",
        action="store_true",
        default=False,
        help="skip tests marked network",
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--no-network") or os.environ.get("HUNTER_NO_NETWORK") == "1":
        skip = pytest.mark.skip(reason="network tests disabled")
        for item in items:
            if "network" in item.keywords:
                item.add_marker(skip)