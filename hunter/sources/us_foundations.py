"""US foundations and corporate funders.

The registry (``hunter/data/foundations_registry.json``) holds ~250 real US
funders. Each entry is one of two modes:

``rss``
    The funder publishes a feed. We GET it with httpx and parse with
    feedparser. If the direct fetch is blocked or returns nothing parseable,
    the feed is re-fetched through Playwright - some funders only serve the
    XML to a browser and return 403 to a plain client.

``scrape``
    No usable feed. Playwright renders the grant/program landing page and a
    generic listing heuristic extracts grant-shaped links.

Both paths filter on grant keywords so newsletters and press releases do not
flood the inbox with "grant" as a substring match on unrelated prose.

When ``STATES_FILTER`` names states, only funders scoped to those states (or
nationwide funders, ``state_code is None``) are contacted.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin

import feedparser
import httpx

from hunter.config import REGISTRY_PATH, get_settings
from hunter.sources.base import (
    SOURCE_NATIONAL_FOUNDATION,
    GrantRecord,
    SourceResult,
    build_client,
    gather_limited,
    parse_deadline,
    playwright_fetch,
    request_text,
    same_site,
    strip_html,
)

logger = logging.getLogger("hunter.sources.us_foundations")

SOURCE = SOURCE_NATIONAL_FOUNDATION
SOURCE_NAME = "us_foundations"

# Anchors that are almost never opportunities even when their text matches.
_NAV_NOISE = {
    "apply", "apply now", "grants", "grant", "funding", "our grants", "grants & funding",
    "grantmaking", "grantmaking approach", "learn more", "read more", "our work",
    "programs", "program", "home", "about", "about us", "contact", "contact us",
    "news", "news & insights", "insights", "blog", "events", "careers", "donate",
    "search", "privacy policy", "terms of use", "sign up", "subscribe",
}


def load_registry(path: Path | None = None) -> list[dict[str, Any]]:
    path = path or REGISTRY_PATH
    if not path.exists():
        logger.warning("foundations registry missing at %s", path)
        return []
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        logger.warning("foundations registry is not a list; ignoring")
        return []
    return data


def filter_registry(
    registry: Iterable[dict[str, Any]], state_codes: list[str]
) -> list[dict[str, Any]]:
    """Nationwide funders always pass; state-scoped funders must match."""
    if state_codes == ["ALL"]:
        return [e for e in registry if e.get("feed_url") or e.get("website")]
    wanted = set(state_codes)
    selected = []
    for entry in registry:
        code = entry.get("state_code")
        if code is None or code in wanted:
            if entry.get("feed_url") or entry.get("website"):
                selected.append(entry)
    return selected


def _matches_keywords(text: str, keywords: list[str]) -> bool:
    lowered = text.casefold()
    return any(kw.casefold() in lowered for kw in keywords)


class USFoundationsSource:
    name = SOURCE_NAME

    def __init__(self, registry: list[dict[str, Any]] | None = None) -> None:
        self.settings = get_settings()
        self.registry = registry if registry is not None else load_registry()

    def select(self, state_codes: list[str] | None = None) -> list[dict[str, Any]]:
        codes = state_codes if state_codes is not None else self.settings.state_codes
        return filter_registry(self.registry, codes)

    # -- Feed parsing -------------------------------------------------------

    @staticmethod
    def parse_feed(xml_text: str, funder: dict[str, Any]) -> list[GrantRecord]:
        parsed = feedparser.parse(xml_text)
        keywords = funder.get("keywords") or []
        records: list[GrantRecord] = []
        feed_title = strip_html(parsed.feed.get("title") or funder.get("name") or "")

        for entry in parsed.entries:
            title = strip_html(entry.get("title") or "")
            if not title:
                continue
            summary = strip_html(_entry_body(entry))
            blob = f"{title} {summary}"
            if keywords and not _matches_keywords(blob, keywords):
                continue
            if title.casefold().strip() in _NAV_NOISE:
                continue

            link = entry.get("link") or funder.get("website")
            published = entry.get("published") or entry.get("updated")
            record = GrantRecord(
                title=title,
                source=SOURCE,
                external_id=entry.get("id") or link,
                agency=funder.get("name"),
                deadline=parse_deadline(_deadline_hint(blob)) or parse_deadline(published),
                description=summary or None,
                url=link,
                state_code=funder.get("state_code"),
                raw_json={
                    "funder_id": funder.get("id"),
                    "funder_name": funder.get("name"),
                    "feed_title": feed_title,
                    "published": published,
                    "mode": "rss",
                },
            )
            records.append(record)
        return records

    @staticmethod
    def parse_listing(html: str, funder: dict[str, Any]) -> list[GrantRecord]:
        """Generic listing extraction for a rendered grant/program page."""
        import re

        keywords = funder.get("keywords") or []
        records: list[GrantRecord] = []
        seen: set[str] = set()

        anchor_re = re.compile(r'<a\b[^>]*href="([^"#]+)"[^>]*>(.*?)</a>', re.S | re.I)
        for match in anchor_re.finditer(html):
            href, inner = match.group(1), match.group(2)
            if href.startswith(("mailto:", "tel:", "javascript:")):
                continue
            text = strip_html(inner)
            if not text or len(text) < 12 or len(text) > 220:
                continue
            if text.casefold().strip() in _NAV_NOISE:
                continue
            if keywords and not _matches_keywords(text, keywords):
                continue

            url = urljoin(funder.get("website") or "", href)
            if not same_site(url, funder.get("website") or ""):
                continue  # keep only this funder's own pages
            if url in seen:
                continue
            seen.add(url)

            records.append(
                GrantRecord(
                    title=text,
                    source=SOURCE,
                    external_id=url,
                    agency=funder.get("name"),
                    deadline=parse_deadline(text),
                    description=None,
                    url=url,
                    state_code=funder.get("state_code"),
                    raw_json={
                        "funder_id": funder.get("id"),
                        "funder_name": funder.get("name"),
                        "mode": "scrape",
                    },
                )
            )
        return records

    # -- Fetching -----------------------------------------------------------

    async def _fetch_funder(self, client: httpx.AsyncClient, funder: dict[str, Any]) -> list[GrantRecord]:
        feed_url = funder.get("feed_url")
        if feed_url:
            text = await request_text(client, "GET", feed_url, source=SOURCE_NAME)
            if text and _looks_like_feed(text):
                records = self.parse_feed(text, funder)
                if records:
                    return records
            # Fall back to a real browser: many funders gate the feed.
            if self.settings.foundations_use_playwright:
                rendered = await playwright_fetch(feed_url, wait_ms=400)
                if rendered and _looks_like_feed(rendered):
                    return self.parse_feed(rendered, funder)

        website = funder.get("website")
        if website and self.settings.foundations_use_playwright:
            rendered = await playwright_fetch(website, wait_for="a", scroll=True)
            if rendered:
                return self.parse_listing(rendered, funder)
        elif website:
            text = await request_text(client, "GET", website, source=SOURCE_NAME)
            if text:
                return self.parse_listing(text, funder)
        return []

    # -- Orchestration ------------------------------------------------------

    async def run(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        state_codes: list[str] | None = None,
        limit: int | None = None,
    ) -> SourceResult:
        result = SourceResult(source=SOURCE_NAME)
        funders = self.select(state_codes)
        if limit:
            funders = funders[:limit]
        if not funders:
            result.skipped = True
            result.skip_reason = "no funders selected for the requested states"
            return result

        owns_client = client is None
        client = client or build_client()

        try:
            def task(funder: dict[str, Any]):
                return lambda: self._fetch_funder(client, funder)

            outcomes = await gather_limited(
                [task(f) for f in funders],
                self.settings.foundations_max_concurrency,
            )

            empty = 0
            for funder, records in zip(funders, outcomes):
                if records is None:
                    result.record_error(f"{funder.get('id')}: fetch failed")
                    continue
                if not records:
                    empty += 1
                    continue
                result.extend(records)

            result.state_breakdown = _breakdown(result.records)
            logger.info(
                "foundations: %s records from %s/%s funders (%s empty)",
                result.found,
                len(funders) - empty,
                len(funders),
                empty,
            )
        except Exception as exc:  # pragma: no cover - defensive
            result.record_error(f"unexpected failure: {exc}")
        finally:
            if owns_client:
                await client.aclose()

        return result


def _looks_like_feed(text: str) -> bool:
    head = text[:2000].casefold()
    return "<rss" in head or "<feed" in head or "<channel" in head or "<?xml" in head


def _entry_body(entry: Any) -> str:
    """feedparser may put the body in `summary` or a `content` list."""
    if entry.get("summary"):
        return entry["summary"]
    if entry.get("description"):
        return entry["description"]
    content = entry.get("content")
    if isinstance(content, list) and content:
        return content[0].get("value") or ""
    return ""


def _deadline_hint(text: str) -> str | None:
    """Pull a deadline phrase out of prose: 'Deadline: March 1, 2027'."""
    import re

    match = re.search(
        r"(?:deadline|due|closes?|applications? due|submissions? due)\s*[:\-]?\s*([A-Za-z0-9 ,/.]{6,40})",
        text,
        re.I,
    )
    return match.group(1).strip() if match else None


def _breakdown(records: list[GrantRecord]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        key = record.state_code or "national"
        counts[key] = counts.get(key, 0) + 1
    return counts


async def fetch_us_foundations(
    *, state_codes: list[str] | None = None, limit: int | None = None
) -> SourceResult:
    return await USFoundationsSource().run(state_codes=state_codes, limit=limit)


__all__ = [
    "USFoundationsSource",
    "fetch_us_foundations",
    "load_registry",
    "filter_registry",
    "SOURCE",
    "SOURCE_NAME",
]