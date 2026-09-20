"""Persistence and scheduler tests against a real Postgres.

These run only when DATABASE_URL points at a reachable Postgres (the default
local cluster). They verify the actual `grants` schema, the dedupe upsert, and
that the Hunter's counters line up with what landed in the table.
"""

from __future__ import annotations

from datetime import date

import pytest

from hunter.db import get_engine, init_db, session_scope
from hunter.models import Grant
from hunter.persistence import persist_records
from hunter.sources.base import GrantRecord

pytestmark = pytest.mark.usefixtures("_db")


@pytest.fixture(scope="module")
def _db():
    engine = get_engine()
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"Postgres not available: {exc}")
    init_db()
    yield


@pytest.fixture
def clean_grants():
    """Remove the rows a test creates, keyed by a distinctive title prefix."""
    yield
    with session_scope() as session:
        session.query(Grant).filter(Grant.title.like("PERSISTTEST%")).delete(
            synchronize_session=False
        )


def _record(n: int, *, deadline=date(2030, 1, 1)) -> GrantRecord:
    return GrantRecord(
        title=f"PERSISTTEST Grant {n}",
        source="federal",
        external_id=f"ext-{n}",
        agency="Test Agency",
        deadline=deadline,
        amount_min=1000,
        amount_max=5000,
        description="A test grant.",
        url=f"https://example.gov/{n}",
        state_code=None,
        raw_json={"n": n},
    )


def test_grants_table_has_expected_columns():
    columns = {c.name for c in Grant.__table__.columns}
    expected = {
        "id", "external_id", "title", "agency", "deadline", "amount_min",
        "amount_max", "description", "url", "raw_json", "source",
        "state_code", "dedupe_hash",
    }
    assert expected <= columns


def test_dedupe_hash_has_unique_constraint():
    constraints = {c.name for c in Grant.__table__.constraints if c.name}
    assert "uq_grants_dedupe_hash" in constraints


def test_persist_inserts_then_updates(clean_grants):
    with session_scope() as session:
        stats = persist_records(session, [_record(1), _record(2)])
    assert stats["inserted"] == 2
    assert stats["updated"] == 0

    # Re-persisting the same opportunities must not duplicate them.
    with session_scope() as session:
        stats2 = persist_records(session, [_record(1), _record(2)])
    assert stats2["inserted"] == 0
    assert stats2["updated"] == 2

    with session_scope() as session:
        rows = session.query(Grant).filter(Grant.title.like("PERSISTTEST%")).all()
        assert len(rows) == 2


def test_persist_collapses_intra_batch_duplicates(clean_grants):
    with session_scope() as session:
        stats = persist_records(session, [_record(5), _record(5)])
    assert stats["inserted"] == 1
    assert stats["updated"] == 0


def test_persist_backfills_missing_fields_on_update(clean_grants):
    with session_scope() as session:
        persist_records(session, [_record(9)])

    enriched = _record(9)
    enriched.amount_max = 999999
    enriched.description = "Now with detail."
    with session_scope() as session:
        persist_records(session, [enriched])

    with session_scope() as session:
        row = session.query(Grant).filter(Grant.title == "PERSISTTEST Grant 9").one()
        assert float(row.amount_max) == 999999
        assert row.description == "Now with detail."


def test_persist_skips_titleless_records():
    with session_scope() as session:
        stats = persist_records(session, [GrantRecord(title="", source="federal")])
    assert stats["skipped"] == 1
    assert stats["inserted"] == 0


def test_persist_empty_input_is_noop():
    with session_scope() as session:
        assert persist_records(session, []) == {"inserted": 0, "updated": 0, "skipped": 0}