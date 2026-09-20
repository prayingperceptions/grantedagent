"""Persist ``GrantRecord`` objects with dedupe-aware upsert."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from hunter.deduper import dedupe_hash
from hunter.models import Grant
from hunter.sources.base import GrantRecord


def persist_records(session: Session, records: list[GrantRecord]) -> dict[str, int]:
    """Upsert records on ``dedupe_hash``; count inserted vs refreshed.

    Uses a plain SELECT on the batch's hashes instead of a Postgres
    ``ON CONFLICT`` so the same code path works against sqlite in tests. The
    batch sizes here are in the hundreds, so the extra query is cheap and the
    unique constraint on ``dedupe_hash`` is the real guard against races.
    """
    stats = {"inserted": 0, "updated": 0, "skipped": 0}
    if not records:
        return stats

    # Collapse intra-batch duplicates first so one run cannot insert the same
    # opportunity twice (grants.gov lists some opportunities under 2 agencies).
    unique: dict[str, GrantRecord] = {}
    for record in records:
        if not record.title:
            stats["skipped"] += 1
            continue
        unique.setdefault(record.dedupe_hash, record)

    hashes = list(unique.keys())
    existing: dict[str, Grant] = {}
    for chunk_start in range(0, len(hashes), 500):
        chunk = hashes[chunk_start : chunk_start + 500]
        rows = session.execute(select(Grant).where(Grant.dedupe_hash.in_(chunk))).scalars()
        for row in rows:
            existing[row.dedupe_hash] = row

    for digest, record in unique.items():
        row = existing.get(digest)
        if row is None:
            session.add(Grant(**record.to_row()))
            stats["inserted"] += 1
        else:
            # Refresh mutable fields; keep first_seen_at intact.
            row.last_seen_at = _now()
            row.amount_min = record.amount_min or row.amount_min
            row.amount_max = record.amount_max or row.amount_max
            row.deadline = record.deadline or row.deadline
            row.url = record.url or row.url
            row.description = record.description or row.description
            row.raw_json = record.raw_json or row.raw_json
            if record.source and record.source != row.source:
                # A state source confirming a federal grant keeps the federal row
                # but we note the additional provenance in raw_json.
                row.raw_json = {**(row.raw_json or {}), "also_seen_in": record.source}
            stats["updated"] += 1

    session.flush()
    return stats


def dedupe_key(record: GrantRecord) -> str:
    return dedupe_hash(record.title, record.agency, record.deadline)


def _now():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)


__all__ = ["persist_records", "dedupe_key"]