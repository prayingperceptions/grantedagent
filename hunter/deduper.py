"""Deterministic dedupe key for grant records.

The hash is built from title + agency + deadline. Those three fields are what
actually identify "the same opportunity" across grants.gov, a state portal,
and a foundation feed that republishes the same call, so hashing them keeps a
grant from being stored once per source.

Normalisation exists purely to stop formatting noise from changing the key:
case, punctuation, whitespace, a missing deadline and a missing agency all
collapse to stable tokens.
"""

from __future__ import annotations

import hashlib
import re
from datetime import date, datetime

_PUNCT = re.compile(r"[^\w\s]", re.UNICODE)
_WS = re.compile(r"\s+")

_EMPTY_AGENCY = "unknown-agency"
_NO_DEADLINE = "no-deadline"


def normalize_text(value: str | None) -> str:
    if not value:
        return ""
    text = value.casefold()
    # Drop possessives before punctuation stripping so "Veteran's" -> "veterans".
    text = text.replace("'s ", "s ").replace("\u2019s ", "s ")
    text = _PUNCT.sub(" ", text)
    return _WS.sub(" ", text).strip()


def normalize_deadline(value: date | datetime | str | None) -> str:
    """Coerce any deadline representation to YYYY-MM-DD, else a sentinel."""
    if value is None:
        return _NO_DEADLINE
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()

    cleaned = str(value).strip()
    if not cleaned:
        return _NO_DEADLINE

    # Already ISO-ish: 2026-10-19 or 2026-10-19T00:00:00
    iso = cleaned[:10]
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", iso):
        return iso

    # US style: 10/19/2026
    m = re.match(r"^(\d{1,2})[/-](\d{1,2})[/-](\d{4})", cleaned)
    if m:
        mm, dd, yyyy = m.groups()
        return f"{yyyy}-{int(mm):02d}-{int(dd):02d}"

    # "Oct 19, 2026" / "October 19, 2026"
    m = re.match(r"^([A-Za-z]{3,9})\.?\s+(\d{1,2}),?\s+(\d{4})", cleaned)
    if m:
        from datetime import datetime as _dt

        for fmt in ("%B %d %Y", "%b %d %Y"):
            try:
                return _dt.strptime(f"{m.group(1)} {m.group(2)} {m.group(3)}", fmt).date().isoformat()
            except ValueError:
                continue

    return normalize_text(cleaned)


def dedupe_hash(
    title: str | None,
    agency: str | None = None,
    deadline: date | datetime | str | None = None,
) -> str:
    """sha256 of ``title|agency|deadline`` after normalisation."""
    title_key = normalize_text(title) or "untitled"
    agency_key = normalize_text(agency) or _EMPTY_AGENCY
    deadline_key = normalize_deadline(deadline)
    payload = f"{title_key}|{agency_key}|{deadline_key}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


__all__ = ["dedupe_hash", "normalize_text", "normalize_deadline"]
