"""Shared pytest fixtures.

Live-network tests are marked ``network`` and run by default (the acceptance
criteria require real federal/foundation data). Unit tests never touch the
network and use the HTML/feed fixtures in tests/fixtures.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from hunter.config import reload_settings

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    """Settings are lru_cached; env changes in a test must take effect."""
    reload_settings()
    yield
    reload_settings()


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


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