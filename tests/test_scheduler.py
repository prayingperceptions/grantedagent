"""Scheduler wiring tests: the 6h interval, the counters, and source grouping.

These use the DB-less path (``persist=False`` across a stubbed-Hunter seam) so
they assert orchestration and logging shape without any network.
"""

from __future__ import annotations

from datetime import datetime, timezone


from hunter.config import reload_settings
from hunter.scheduler import HuntResult, build_scheduler, _merge_breakdowns
from hunter.sources.base import GrantRecord, SourceResult


def test_hunt_result_serializes_all_required_counters():
    result = HuntResult()
    result.federal_found = 25
    result.foundation_found = 7
    result.state_total = 3
    result.state_breakdown = {"WI": 3}
    result.finished_at = datetime.now(timezone.utc)

    payload = result.as_log_dict()
    for key in ("federal_found", "foundation_found", "state_total", "state_breakdown"):
        assert key in payload
    assert payload["federal_found"] == 25
    assert payload["foundation_found"] == 7
    assert payload["state_breakdown"] == {"WI": 3}


def test_scheduler_interval_defaults_to_6_hours(monkeypatch):
    monkeypatch.delenv("SCHEDULER_INTERVAL_HOURS", raising=False)
    reload_settings()
    scheduler = build_scheduler(blocking=False, run_on_start=False)
    scheduler.start(paused=True)
    try:
        job = scheduler.get_job("hunter.hunt")
        assert job is not None
        # IntervalTrigger stores the interval on the trigger.
        assert int(job.trigger.interval.total_seconds()) == 6 * 3600
        assert job.max_instances == 1
        assert job.coalesce is True
    finally:
        scheduler.shutdown(wait=False)


def test_scheduler_interval_is_configurable(monkeypatch):
    monkeypatch.setenv("SCHEDULER_INTERVAL_HOURS", "12")
    reload_settings()
    scheduler = build_scheduler(blocking=False, run_on_start=False)
    scheduler.start(paused=True)
    try:
        job = scheduler.get_job("hunter.hunt")
        assert int(job.trigger.interval.total_seconds()) == 12 * 3600
    finally:
        scheduler.shutdown(wait=False)


def test_merge_breakdowns_sums_across_sources():
    a = SourceResult(source="state_local_scraper")
    a.state_breakdown = {"WI": 2, "MN": 1}
    b = SourceResult(source="other")
    b.state_breakdown = {"WI": 3}
    assert _merge_breakdowns([a, b]) == {"MN": 1, "WI": 5}


def test_source_result_tracks_skips_and_found():
    skipped = SourceResult(source="sam_gov")
    skipped.skipped = True
    skipped.skip_reason = "SAM_GOV_API_KEY not set"
    assert skipped.found == 0

    found = SourceResult(source="grants_gov")
    found.records = [GrantRecord(title=f"Grant {i}", source="federal") for i in range(5)]
    assert found.found == 5


async def test_hunter_orchestration_groups_and_counts(monkeypatch):
    """Hunter.hunt must group sources and populate the required counters."""
    from hunter import scheduler as scheduler_mod

    async def fake_federal(self, client, max_detail_lookups):
        r = SourceResult(source="grants_gov")
        r.records = [GrantRecord(title=f"Federal {i}", source="federal", agency="A") for i in range(3)]
        return [r]

    async def fake_foundations(self, client, states):
        r = SourceResult(source="us_foundations")
        r.records = [
            GrantRecord(title=f"Foundation {i}", source="national_foundation", agency="F")
            for i in range(2)
        ]
        return [r]

    async def fake_states(self, client, states):
        r = SourceResult(source="state_local_scraper")
        r.state_breakdown = {"WI": 1}
        r.records = [
            GrantRecord(title="WI Grant", source="state_WI", state_code="WI", agency="WI")
        ]
        return [r]

    monkeypatch.setattr(scheduler_mod.Hunter, "_run_federal", fake_federal)
    monkeypatch.setattr(scheduler_mod.Hunter, "_run_foundations", fake_foundations)
    monkeypatch.setattr(scheduler_mod.Hunter, "_run_states", fake_states)

    result = await scheduler_mod.Hunter().hunt(persist=False)

    assert result.federal_found == 3
    assert result.foundation_found == 2
    assert result.state_total == 1
    assert result.state_breakdown == {"WI": 1}
    assert result.total_unique == 6
    assert result.errors == {}