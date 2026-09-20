"""Acceptance tests for the Hunter.

The stated acceptance criteria:

    STATES_FILTER=ALL  -> 20+ federal and 5+ foundation opportunities
    STATES_FILTER=WI   -> Wisconsin opportunities present

These hit the live grants.gov API and real foundation feeds, so they are marked
``network``. Run with ``pytest -m network`` or skip via ``--no-network``.
"""

from __future__ import annotations

import pytest

from hunter.config import reload_settings
from hunter.sources.grants_gov import fetch_grants
from hunter.sources.us_foundations import USFoundationsSource
from hunter.sources.state_local_scraper import StateLocalScraper, resolve_states

pytestmark = pytest.mark.network


async def test_acceptance_all_finds_20_plus_federal():
    """STATES_FILTER=ALL must surface at least 20 federal opportunities."""
    result = await fetch_grants()
    assert result.ok, f"grants.gov errored: {result.errors}"
    assert result.found >= 20, f"expected 20+ federal, got {result.found}"

    for record in result.records:
        assert record.source == "federal"
        assert record.title
        assert record.external_id
        assert record.url
        assert record.dedupe_hash


async def test_acceptance_all_finds_5_plus_foundations():
    """STATES_FILTER=ALL must surface at least 5 foundation opportunities.

    The registry is tried in order; we only need 5 successes, so a handful of
    slow or blocked funders should not fail the run.
    """
    source = USFoundationsSource()
    selected = source.select(["ALL"])
    assert len(selected) >= 200, "nationwide run should consider 200+ funders"

    result = await source.run(state_codes=["ALL"], limit=25)
    assert result.found >= 5, f"expected 5+ foundations, got {result.found} ({result.errors})"

    for record in result.records:
        assert record.source == "national_foundation"
        assert record.title
        assert record.agency


async def test_acceptance_wi_only_returns_wisconsin():
    """STATES_FILTER=WI must produce Wisconsin-scoped opportunities."""
    scraper = StateLocalScraper()
    result = await scraper.run(state_codes=["WI"])

    assert result.found >= 1, f"expected WI records, got {result.found} ({result.errors})"
    for record in result.records:
        assert record.source == "state_WI"
        assert record.state_code == "WI"
    assert result.state_breakdown.get("WI", 0) >= 1

    # WI portal configs must be present and only WI funders contacted.
    funder_source = USFoundationsSource()
    wi_funders = funder_source.select(["WI"])
    assert wi_funders
    assert all(e.get("state_code") in (None, "WI") for e in wi_funders)


def test_states_filter_env_drives_resolution(monkeypatch):
    """The env var, not just the argument, must control scope."""
    monkeypatch.setenv("STATES_FILTER", "WI")
    settings = reload_settings()
    assert settings.state_codes == ["WI"]
    assert not settings.is_nationwide
    assert resolve_states() == ["WI"]

    monkeypatch.setenv("STATES_FILTER", "ALL")
    settings = reload_settings()
    assert settings.is_nationwide
    assert len(resolve_states()) == 51

    monkeypatch.setenv("STATES_FILTER", "wi, mn")
    settings = reload_settings()
    assert settings.state_codes == ["WI", "MN"]
    assert resolve_states() == ["MN", "WI"]