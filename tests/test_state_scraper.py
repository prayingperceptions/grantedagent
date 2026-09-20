"""State scraper tests: config coverage, STATES_FILTER resolution, extraction."""

from __future__ import annotations

import json

import pytest

from hunter.sources.state_local_scraper import (
    StateLocalScraper,
    available_states,
    load_state_config,
    resolve_states,
)

EXPECTED_STATES = {
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "DC", "FL", "GA", "HI",
    "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN",
    "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY", "NC", "ND", "OH",
    "OK", "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA",
    "WV", "WI", "WY",
}


def test_all_50_states_plus_dc_have_configs():
    states = set(available_states())
    assert states == EXPECTED_STATES
    assert len(states) == 51


@pytest.mark.parametrize("code", sorted(EXPECTED_STATES))
def test_each_state_config_is_well_formed(code):
    config = load_state_config(code)
    assert config is not None
    assert config["state_code"] == code
    assert config["state_name"]
    assert config["portals"], f"{code} must define at least one portal"
    for portal in config["portals"]:
        assert portal["name"]
        assert portal["url"].startswith("http")
        assert portal["mode"] in {"http", "playwright"}
        assert portal["keywords"]
        assert isinstance(portal["max_items"], int)


def test_resolve_all_returns_every_state():
    assert resolve_states(["ALL"]) == sorted(EXPECTED_STATES)


def test_resolve_single_and_multiple_states():
    assert resolve_states(["WI"]) == ["WI"]
    assert resolve_states(["wi"]) == ["WI"]
    assert resolve_states(["WI", "MN", "CA"]) == ["CA", "MN", "WI"]


def test_resolve_ignores_unknown_codes():
    assert resolve_states(["ZZ"]) == []
    assert resolve_states(["WI", "ZZ"]) == ["WI"]


def test_wisconsin_config_has_verified_portals():
    config = load_state_config("WI")
    verified = [p for p in config["portals"] if p.get("verified")]
    assert verified, "WI must have at least one verified portal"


def test_extract_jsonld_structured_listing():
    html = """
    <html><head>
    <script type="application/ld+json">
    {"@context":"https://schema.org","@type":"ItemList","itemListElement":[
      {"@type":"GovernmentService","name":"Rural Broadband Expansion Grant Program",
       "url":"https://example.gov/grants/broadband",
       "description":"Funding for broadband infrastructure in rural counties.",
       "endDate":"2027-03-15"}
    ]}
    </script></head><body></body></html>
    """
    portal = {"name": "Example State Grants", "url": "https://example.gov/grants",
              "keywords": ["grant", "funding"]}
    records = StateLocalScraper.extract_jsonld(html, portal, "WI")
    assert len(records) == 1
    record = records[0]
    assert record.source == "state_WI"
    assert record.state_code == "WI"
    assert record.title == "Rural Broadband Expansion Grant Program"
    assert record.deadline is not None and record.deadline.isoformat() == "2027-03-15"
    assert record.url == "https://example.gov/grants/broadband"


def test_extract_next_data():
    payload = {
        "props": {
            "pageProps": {
                "grants": [
                    {
                        "id": 42,
                        "title": "Community Food Security Grant",
                        "url": "/grants/food-security",
                        "deadline": "04/30/2027",
                        "awardAmount": "$75,000",
                        "description": "Supports local food banks.",
                    }
                ]
            }
        }
    }
    html = f'<html><script id="__NEXT_DATA__" type="application/json">{json.dumps(payload)}</script></html>'
    portal = {"name": "State Grants", "url": "https://example.gov/grants", "keywords": ["grant"]}
    records = StateLocalScraper.extract_next_data(html, portal, "CA")
    assert len(records) == 1
    record = records[0]
    assert record.source == "state_CA"
    assert record.amount_max == 75000.0
    assert record.deadline is not None and record.deadline.isoformat() == "2027-04-30"
    assert record.url == "https://example.gov/grants/food-security"


def test_extract_links_respects_keywords_and_domain():
    html = """
    <html><body>
      <a href="/grants/youth-mental-health">Youth Mental Health Services Grant Program</a>
      <a href="/about">About our agency</a>
      <a href="https://othersite.com/grants/fake">Fake Grant Program Opportunity</a>
      <a href="/grants/water-quality">Clean Water Quality Improvement Funding</a>
    </body></html>
    """
    portal = {"name": "State Grants", "url": "https://agency.example.gov/grants",
              "keywords": ["grant", "funding"], "max_items": 10}
    records = StateLocalScraper.extract_links(html, portal, "MN")
    urls = {r.url for r in records}
    assert "https://agency.example.gov/grants/youth-mental-health" in urls
    assert "https://agency.example.gov/grants/water-quality" in urls
    assert "https://agency.example.gov/about" not in urls
    assert all("othersite.com" not in u for u in urls)
    assert all(r.source == "state_MN" for r in records)


def test_extract_links_deduplicates():
    html = """
    <html><body>
      <a href="/grants/same-program">Housing Assistance Grant Program</a>
      <a href="/grants/same-program">Housing Assistance Grant Program</a>
    </body></html>
    """
    portal = {"name": "S", "url": "https://s.gov/grants", "keywords": ["grant"], "max_items": 10}
    records = StateLocalScraper.extract_links(html, portal, "TX")
    assert len(records) == 1