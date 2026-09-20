"""The Hunter's heartbeat.

Runs every ``SCHEDULER_INTERVAL_HOURS`` (6 by default):

1. federal  - grants.gov (always), Simpler Grants and SAM.gov when keyed.
2. foundations - the national registry, filtered by the active states.
3. state/local - every state in ``STATES_FILTER``.

One tick is a ``HuntResult``:

    federal_found            records from federal sources
    foundation_found         records from foundations
    state_total              records from state/local portals
    state_breakdown          {state_code: count}
    inserted / updated / total_unique   what actually landed in Postgres

The scheduler never raises: a source blowing up is captured in ``errors`` and
logged. That matters because this runs unattended on a 6 hour cadence over
~250 funders and 51 states.

Two entry points:

    python -m hunter.scheduler --once     single tick, prints a summary
    python -m hunter.scheduler            blocking scheduler loop
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.interval import IntervalTrigger

from hunter.config import get_settings
from hunter.db import init_db, session_scope
from hunter.models import HunterRun
from hunter.persistence import persist_records
from hunter.sources.base import GrantRecord, SourceResult, build_client, run_async
from hunter.sources.grants_gov import GrantsGovSource
from hunter.sources.sam_gov import SamGovSource
from hunter.sources.simpler_grants import SimplerGrantsSource
from hunter.sources.state_local_scraper import StateLocalScraper, resolve_states
from hunter.sources.us_foundations import USFoundationsSource

logger = logging.getLogger("hunter.scheduler")

JOB_ID = "hunter.hunt"


@dataclass
class HuntResult:
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    federal_found: int = 0
    foundation_found: int = 0
    state_total: int = 0
    state_breakdown: dict[str, int] = field(default_factory=dict)
    inserted: int = 0
    updated: int = 0
    total_unique: int = 0
    coverage: dict[str, int] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    source_detail: dict[str, int] = field(default_factory=dict)
    skipped: dict[str, str] = field(default_factory=dict)

    def as_log_dict(self) -> dict:
        return {
            "started_at": self.started_at.isoformat(),
            "finished_at": (self.finished_at or datetime.now(timezone.utc)).isoformat(),
            "federal_found": self.federal_found,
            "foundation_found": self.foundation_found,
            "state_total": self.state_total,
            "state_breakdown": self.state_breakdown,
            "inserted": self.inserted,
            "updated": self.updated,
            "total_unique": self.total_unique,
            "coverage": self.coverage,
            "source_detail": self.source_detail,
            "skipped": self.skipped,
            "errors": self.errors,
        }


class Hunter:
    """Orchestrates every source and writes the results to Postgres."""

    def __init__(self) -> None:
        self.settings = get_settings()

    async def hunt(
        self,
        *,
        states: list[str] | None = None,
        persist: bool = True,
        max_detail_lookups: int = 0,
    ) -> HuntResult:
        result = HuntResult()
        codes = resolve_states(states)
        result.coverage["states_requested"] = self.settings.states_filter
        result.coverage["states_resolved"] = len(codes)

        async with build_client() as client:
            federal_results = await self._run_federal(client, max_detail_lookups)
            foundation_results = await self._run_foundations(client, states)
            state_results = await self._run_states(client, states)

        all_records: list[GrantRecord] = []
        for source_result in federal_results:
            all_records.extend(source_result.records)
        for source_result in foundation_results:
            all_records.extend(source_result.records)
        for source_result in state_results:
            all_records.extend(source_result.records)

        result.federal_found = sum(r.found for r in federal_results)
        result.foundation_found = sum(r.found for r in foundation_results)
        result.state_total = sum(r.found for r in state_results)
        result.state_breakdown = _merge_breakdowns(state_results)
        result.total_unique = len({r.dedupe_hash for r in all_records})

        for source_result in [*federal_results, *foundation_results, *state_results]:
            name = source_result.source
            if source_result.skipped:
                result.skipped[name] = source_result.skip_reason or "skipped"
            if source_result.found:
                result.source_detail[name] = source_result.found
            for error in source_result.errors:
                result.errors[name] = error

        if all_records and persist:
            try:
                init_db()
                with session_scope() as session:
                    stats = persist_records(session, all_records)
                result.inserted = stats["inserted"]
                result.updated = stats["updated"]
            except Exception as exc:
                logger.exception("persistence failed")
                result.errors["persistence"] = str(exc)

        result.finished_at = datetime.now(timezone.utc)
        self._log_summary(result)
        if persist:
            self._record_run(result)
        return result

    # -- source groups ----------------------------------------------------

    async def _run_federal(self, client, max_detail_lookups: int) -> list[SourceResult]:
        results: list[SourceResult] = []
        try:
            results.append(
                await GrantsGovSource(max_detail_lookups=max_detail_lookups).run(client=client)
            )
        except Exception as exc:
            results.append(_failed("grants_gov", exc))

        for source in (SimplerGrantsSource(), SamGovSource()):
            try:
                results.append(await source.run(client=client))
            except Exception as exc:
                results.append(_failed(source.name, exc))
        return results

    async def _run_foundations(self, client, states: list[str] | None) -> list[SourceResult]:
        try:
            return [await USFoundationsSource().run(client=client, state_codes=states)]
        except Exception as exc:
            return [_failed("us_foundations", exc)]

    async def _run_states(self, client, states: list[str] | None) -> list[SourceResult]:
        try:
            return [await StateLocalScraper().run(client=client, state_codes=states)]
        except Exception as exc:
            return [_failed("state_local_scraper", exc)]

    # -- logging / persistence -------------------------------------------

    def _log_summary(self, result: HuntResult) -> None:
        logger.info(
            "hunt done: federal_found=%s foundation_found=%s state_total=%s "
            "state_breakdown=%s inserted=%s updated=%s total_unique=%s",
            result.federal_found,
            result.foundation_found,
            result.state_total,
            json.dumps(result.state_breakdown, sort_keys=True),
            result.inserted,
            result.updated,
            result.total_unique,
        )
        logger.debug("hunt detail: %s", json.dumps(result.as_log_dict(), default=str))

    def _record_run(self, result: HuntResult) -> None:
        try:
            with session_scope() as session:
                session.add(
                    HunterRun(
                        started_at=result.started_at,
                        finished_at=result.finished_at,
                        federal_found=result.federal_found,
                        foundation_found=result.foundation_found,
                        state_total=result.state_total,
                        state_breakdown=result.state_breakdown,
                        errors=result.errors or None,
                    )
                )
        except Exception as exc:  # auditing must never break the hunt
            logger.warning("could not record run: %s", exc)


def _failed(source: str, exc: Exception) -> SourceResult:
    result = SourceResult(source=source)
    result.record_error(f"unhandled {type(exc).__name__}: {exc}")
    return result


def _merge_breakdowns(results: list[SourceResult]) -> dict[str, int]:
    merged: dict[str, int] = {}
    for result in results:
        for code, count in result.state_breakdown.items():
            merged[code] = merged.get(code, 0) + count
    return dict(sorted(merged.items()))


# --------------------------------------------------------------------------
# Job wiring
# --------------------------------------------------------------------------


def run_hunt_once(states: list[str] | None = None, *, persist: bool = True, max_detail_lookups: int = 0) -> HuntResult:
    """Sync wrapper used by the scheduler and the CLI."""
    return run_async(Hunter().hunt(states=states, persist=persist, max_detail_lookups=max_detail_lookups))


def build_scheduler(*, blocking: bool = True, run_on_start: bool | None = None):
    """Configure APScheduler with the 6h hunt job.

    ``coalesce`` and ``max_instances=1`` keep a slow nationwide crawl from
    stacking ticks on top of each other; ``misfire_grace_time`` lets a tick that
    was missed while the process was down still run once.
    """
    settings = get_settings()
    scheduler_cls = BlockingScheduler if blocking else BackgroundScheduler
    scheduler = scheduler_cls(timezone="UTC")

    scheduler.add_job(
        run_hunt_once,
        trigger=IntervalTrigger(hours=settings.scheduler_interval_hours),
        id=JOB_ID,
        name=f"hunter hunt every {settings.scheduler_interval_hours}h",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=1800,
        replace_existing=True,
    )

    if run_on_start is None:
        run_on_start = settings.scheduler_run_on_start
    if run_on_start:
        logger.info("running an immediate hunt before the first interval")
        run_hunt_once()

    logger.info(
        "scheduler armed: every %sh, states_filter=%s",
        settings.scheduler_interval_hours,
        settings.states_filter,
    )
    return scheduler


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Granted Agent - the Hunter")
    parser.add_argument("--once", action="store_true", help="run a single hunt and exit")
    parser.add_argument("--states", help="override STATES_FILTER, e.g. WI or WI,MN")
    parser.add_argument("--no-persist", action="store_true", help="skip the database write")
    parser.add_argument("--detail-lookups", type=int, default=0, help="grants.gov detail enrichment cap")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    _configure_logging(args.verbose)
    states = [s.strip().upper() for s in args.states.split(",")] if args.states else None

    if args.once:
        result = run_hunt_once(states, persist=not args.no_persist, max_detail_lookups=args.detail_lookups)
        print(json.dumps(result.as_log_dict(), indent=2, default=str))
        return 0 if not result.errors else 1

    scheduler = build_scheduler(blocking=True)

    def _shutdown(signum, frame):  # pragma: no cover - signal path
        logger.info("signal %s received, shutting down", signum)
        scheduler.shutdown(wait=False)
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):  # pragma: no cover
        scheduler.shutdown(wait=False)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())