"""Unit tests: dedupe, parsing, and source parsers against real fixtures.

No network and no mocks of the parsing logic - the fixtures are byte-for-byte
captures of real API responses, so these tests exercise the same code paths the
scheduler uses.
"""

from __future__ import annotations

import json
from datetime import date

import pytest

from hunter.deduper import dedupe_hash, normalize_deadline, normalize_text
from hunter.sources.base import (
    GrantRecord,
    parse_amount,
    parse_deadline,
    same_site,
    strip_html,
)
from hunter.sources.grants_gov import GrantsGovSource
from hunter.sources.us_foundations import (
    USFoundationsSource,
    filter_registry,
    load_registry,
)

# --------------------------------------------------------------------------
# deduper
# --------------------------------------------------------------------------


def test_dedupe_hash_is_stable_across_formatting():
    a = dedupe_hash("Community Health Grant Program", "HRSA", "10/19/2026")
    b = dedupe_hash("community health grant program", "HRSA", "2026-10-19")
    c = dedupe_hash("Community Health Grant Program!", "  HRSA ", date(2026, 10, 19))
    assert a == b == c
    assert len(a) == 64


def test_dedupe_hash_distinguishes_real_differences():
    base = dedupe_hash("Health Grant", "HRSA", "2026-10-19")
    assert base != dedupe_hash("Health Grant", "HRSA", "2026-10-20")
    assert base != dedupe_hash("Health Grant", "NIH", "2026-10-19")
    assert base != dedupe_hash("Education Grant", "HRSA", "2026-10-19")


def test_dedupe_hash_handles_missing_agency_and_deadline():
    with_unknown = dedupe_hash("Some Grant", None, None)
    assert with_unknown == dedupe_hash("Some Grant", "", "")
    assert with_unknown != dedupe_hash("Some Grant", None, "2026-01-01")


def test_normalize_deadline_formats():
    assert normalize_deadline("Oct 19, 2026") == "2026-10-19"
    assert normalize_deadline("2026-10-19T12:00:00") == "2026-10-19"
    assert normalize_deadline(date(2026, 10, 19)) == "2026-10-19"
    assert normalize_deadline(None) == "no-deadline"
    assert normalize_deadline("Rolling") == "rolling"


def test_normalize_text_strips_possessives_and_punctuation():
    assert normalize_text("Veteran's Health & Wellness (FY27)") == "veterans health wellness fy27"


# --------------------------------------------------------------------------
# base parsing helpers
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("$50,000", 50000.0),
        ("50000", 50000.0),
        ("$1.2M", 1200000.0),
        ("250K", 250000.0),
        ("Up to $5,000,000", 5000000.0),
        ("1B", 1_000_000_000.0),
        (650000, 650000.0),
        ("N/A", None),
        ("", None),
        (None, None),
        (0, None),
    ],
)
def test_parse_amount(raw, expected):
    assert parse_amount(raw) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("10/19/2026", date(2026, 10, 19)),
        ("2026-10-19", date(2026, 10, 19)),
        ("October 19, 2026", date(2026, 10, 19)),
        ("Oct 19, 2026 12:00:00 AM EDT", date(2026, 10, 19)),
        ("Rolling basis", None),
        ("ongoing", None),
        (None, None),
        ("", None),
    ],
)
def test_parse_deadline(raw, expected):
    assert parse_deadline(raw) == expected


def test_strip_html_collapses_markup_and_entities():
    assert strip_html("<p>Hello &amp; welcome</p>\n<div>to the   program</div>") == "Hello & welcome to the program"


def test_same_site_allows_portal_subdomains():
    assert same_site("https://det.wi.gov/Pages/Grants.aspx", "https://doa.wi.gov/Pages/Grants.aspx")
    assert same_site("https://www.wisconsin.edu/grants-awards/x/", "https://www.wisconsin.edu/grants-awards/")
    assert not same_site("https://example.com/grants", "https://wisconsin.edu/grants")


# --------------------------------------------------------------------------
# grants.gov parser
# --------------------------------------------------------------------------


@pytest.fixture
def search2_payload(fixtures_dir):
    return json.loads((fixtures_dir / "grants_gov_search2.json").read_text())


def test_grants_gov_parses_real_search_response(search2_payload):
    hits = search2_payload["data"]["oppHits"]
    assert hits, "fixture should contain opportunities"

    records = [GrantsGovSource.parse_hit(h) for h in hits]
    records = [r for r in records if r is not None]
    assert len(records) == len(hits)

    first = records[0]
    assert first.source == "federal"
    assert first.title
    assert first.agency
    assert first.external_id
    assert first.url and "grants.gov" in first.url
    assert first.state_code is None
    assert isinstance(first.dedupe_hash, str) and len(first.dedupe_hash) == 64
    # Every parsed deadline must be a date or None, never a string.
    for record in records:
        assert record.deadline is None or isinstance(record.deadline, date)


def test_grants_gov_detail_backfill(fixtures_dir):
    detail = json.loads((fixtures_dir / "grants_gov_fetch_opportunity.json").read_text())
    record = GrantRecord(title="placeholder", source="federal")
    GrantsGovSource.apply_detail(record, detail)

    assert record.amount_max == 10116100.0
    assert record.amount_min == 650000.0
    assert record.agency == "Health Resources and Services Administration"
    assert record.deadline == date(2026, 10, 19)
    assert record.description and len(record.description) > 50


def test_grants_gov_skips_titles_that_are_empty():
    assert GrantsGovSource.parse_hit({"id": 1, "title": "   "}) is None
    assert GrantsGovSource.parse_hit({}) is None


# --------------------------------------------------------------------------
# foundations
# --------------------------------------------------------------------------


def test_registry_has_at_least_200_funders():
    registry = load_registry()
    assert len(registry) >= 200, f"expected 200+ funders, found {len(registry)}"
    ids = [e["id"] for e in registry]
    assert len(ids) == len(set(ids)), "funder ids must be unique"
    for entry in registry:
        assert entry["name"]
        assert entry["website"].startswith("https://")
        assert entry["mode"] in {"rss", "scrape"}


def test_registry_filters_by_state():
    registry = load_registry()
    wi = filter_registry(registry, ["WI"])
    assert wi, "should select Wisconsin + nationwide funders"
    assert all(e.get("state_code") in (None, "WI") for e in wi)
    # Wisconsin-specific funders must be present.
    assert any(e.get("state_code") == "WI" for e in wi)

    national = filter_registry(registry, ["ALL"])
    assert len(national) >= len(wi)


def test_parse_foundation_feed(fixtures_dir):
    xml = (fixtures_dir / "foundation_hewlett.xml").read_text()
    funder = {
        "id": "hewlett",
        "name": "The William and Flora Hewlett Foundation",
        "state_code": None,
        "website": "https://www.hewlett.org/",
        "keywords": ["grant", "funding", "award", "apply", "philanthropy", "program", "fellowship"],
    }
    records = USFoundationsSource.parse_feed(xml, funder)
    assert records, "real Hewlett feed should yield records"
    for record in records:
        assert record.source == "national_foundation"
        assert record.agency == funder["name"]
        assert record.title
        assert record.url


def test_parse_foundation_listing(fixtures_dir):
    html = (fixtures_dir / "wi_uw_grants.html").read_text()
    funder = {
        "id": "uw-system",
        "name": "UW System",
        "state_code": "WI",
        "website": "https://www.wisconsin.edu/grants-awards/",
        "keywords": ["grant", "award", "funding"],
    }
    records = USFoundationsSource.parse_listing(html, funder)
    assert records, "UW grants page should yield grant-shaped links"
    assert all(r.state_code == "WI" for r in records)
    assert all("wisconsin.edu" in (r.url or "") for r in records)
    assert all(len(r.title) >= 12 for r in records)


def test_listing_extraction_excludes_offsite_links():
    html = '<html><body><a href="https://evil.example/grant-money">Grant money here</a>' \
           '<a href="/grants/real-program">Real grant program opportunity</a></body></html>'
    funder = {"id": "x", "name": "X", "state_code": None,
              "website": "https://www.example.org/", "keywords": ["grant"]}
    records = USFoundationsSource.parse_listing(html, funder)
    assert len(records) == 1
    assert records[0].url == "https://www.example.org/grants/real-program"