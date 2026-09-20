"""State and local government grant portals - all 50 states + DC.

Scope is driven by ``STATES_FILTER``:

    STATES_FILTER=ALL          every state config in hunter/states/
    STATES_FILTER=WI           just Wisconsin
    STATES_FILTER=WI,MN,CA     a batch

Portals whose config says ``mode: http`` are fetched with httpx (fast, and the
default for statically served pages). Everything else goes through Playwright
because state portals are typically JS single-page apps whose listings do not
exist in the raw HTML.

Extraction runs in two passes per page:

1. Structured pass - if the rendered HTML contains JSON-LD ``ItemList`` /
   ``Event`` / ``GovernmentService`` nodes or a ``__NEXT_DATA__`` blob, parse
   that. It is exact when present.
2. Heuristic pass - regex over anchors, keeping only same-domain links whose
   text looks like an opportunity (``keywords`` in the state config). This is
   what actually carries the crawl today, since portal markup is bespoke.

Every state is written with ``source="state_<CODE>"`` and ``state_code`` set,
so a query for Wisconsin can be answered with an index scan on ``source``.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from hunter.config import STATES_DIR, get_settings
from hunter.sources.base import (
    SOURCE_STATE_PREFIX,
    GrantRecord,
    SourceResult,
    build_client,
    gather_limited,
    parse_amount,
    parse_deadline,
    playwright_fetch,
    request_text,
    same_site,
    strip_html,
)

logger = logging.getLogger("hunter.sources.state_local")

SOURCE_NAME = "state_local_scraper"

_NAV_NOISE = {
    "apply", "apply now", "learn more", "read more", "view all", "see all",
    "home", "about", "contact", "news", "events", "search", "login", "register",
    "menu", "next", "previous", "back", "more", "details", "view",
}

_ANCHOR_RE = re.compile(r'<a\b[^>]*href="([^"#]+)"[^>]*>(.*?)</a>', re.S | re.I)
_SCRIPT_JSON_RE = re.compile(
    r'<script[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', re.S | re.I
)
_NEXT_DATA_RE = re.compile(
    r'<script[^>]*id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', re.S | re.I
)


def available_states() -> list[str]:
    return sorted(p.stem.upper() for p in STATES_DIR.glob("*.json"))


def resolve_states(state_codes: list[str] | None = None) -> list[str]:
    """Map a STATES_FILTER value onto config files that actually exist."""
    codes = state_codes if state_codes is not None else get_settings().state_codes
    known = set(available_states())
    if codes == ["ALL"]:
        return sorted(known)
    resolved = [c.upper() for c in codes if c.upper() in known]
    unknown = [c for c in codes if c.upper() not in known]
    if unknown:
        logger.warning("STATES_FILTER contains unknown state codes: %s", ",".join(unknown))
    # Sorted so a multi-state run produces a stable breakdown across ticks.
    return sorted(resolved)


def load_state_config(code: str) -> dict[str, Any] | None:
    path = STATES_DIR / f"{code.lower()}.json"
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


class StateLocalScraper:
    name = SOURCE_NAME

    def __init__(self, *, states_dir: Path | None = None) -> None:
        self.settings = get_settings()
        self.states_dir = states_dir or STATES_DIR

    # -- Extraction ---------------------------------------------------------

    @staticmethod
    def extract_jsonld(html: str, portal: dict[str, Any], state_code: str) -> list[GrantRecord]:
        """Parse schema.org nodes embedded in the page."""
        records: list[GrantRecord] = []
        for match in _SCRIPT_JSON_RE.finditer(html):
            try:
                payload = json.loads(match.group(1).strip())
            except (ValueError, TypeError):
                continue
            for node in _iter_nodes(payload):
                record = _record_from_jsonld(node, portal, state_code)
                if record is not None:
                    records.append(record)
        return records

    @staticmethod
    def extract_next_data(html: str, portal: dict[str, Any], state_code: str) -> list[GrantRecord]:
        """Walk __NEXT_DATA__ for objects that look like opportunities."""
        match = _NEXT_DATA_RE.search(html)
        if not match:
            return []
        try:
            payload = json.loads(match.group(1))
        except (ValueError, TypeError):
            return []

        records: list[GrantRecord] = []
        for node in _iter_dicts(payload):
            title = node.get("title") or node.get("name") or node.get("grantTitle")
            if not isinstance(title, str) or len(title) < 12 or len(title) > 220:
                continue
            url = node.get("url") or node.get("link") or node.get("href")
            records.append(
                _make_record(
                    title=title,
                    url=urljoin(portal.get("url") or "", url) if url else portal.get("url"),
                    state_code=state_code,
                    portal=portal,
                    deadline_raw=node.get("deadline") or node.get("closeDate") or node.get("dueDate"),
                    amount_raw=node.get("amount") or node.get("awardAmount") or node.get("fundingAmount"),
                    description=node.get("description") or node.get("summary"),
                    external_id=str(node.get("id") or url or title)[:255],
                    raw=node,
                )
            )
            if len(records) >= portal.get("max_items", 60):
                break
        return records

    @staticmethod
    def extract_links(html: str, portal: dict[str, Any], state_code: str) -> list[GrantRecord]:
        """Heuristic anchor scan, scoped to the portal's own domain."""
        keywords = [k.casefold() for k in portal.get("keywords") or []]
        records: list[GrantRecord] = []
        seen: set[str] = set()
        max_items = portal.get("max_items", 60)

        for match in _ANCHOR_RE.finditer(html):
            href, inner = match.group(1), match.group(2)
            if href.startswith(("mailto:", "tel:", "javascript:")):
                continue
            text = strip_html(inner)
            if not text or len(text) < 15 or len(text) > 220:
                continue
            if text.casefold().strip() in _NAV_NOISE:
                continue
            if keywords and not any(k in text.casefold() for k in keywords):
                continue

            url = urljoin(portal.get("url") or "", href)
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                continue
            # Keep the portal's own site (same registrable domain).
            if not same_site(url, portal.get("url") or ""):
                continue
            if url in seen:
                continue
            seen.add(url)

            records.append(
                _make_record(
                    title=text,
                    url=url,
                    state_code=state_code,
                    portal=portal,
                    deadline_raw=_deadline_near(html, href) or text,
                    amount_raw=_amount_near(text) or None,
                    description=None,
                    external_id=url[:255],
                    raw={"portal": portal.get("name"), "href": href},
                )
            )
            if len(records) >= max_items:
                break
        return records

    # -- Fetching -----------------------------------------------------------

    async def scrape_portal(
        self, client: httpx.AsyncClient, portal: dict[str, Any], state_code: str
    ) -> list[GrantRecord]:
        url = portal.get("url")
        if not url:
            return []

        html: str | None = None
        if portal.get("mode") == "http":
            html = await request_text(client, "GET", url, source=SOURCE_NAME)
        if html is None:
            html = await playwright_fetch(
                url, wait_for="a", wait_ms=600, scroll=True, timeout_ms=int(self.settings.states_timeout_s * 1000)
            )
        if not html:
            return []

        records: list[GrantRecord] = []
        records.extend(self.extract_jsonld(html, portal, state_code))
        if not records:
            records.extend(self.extract_next_data(html, portal, state_code))
        if not records:
            records.extend(self.extract_links(html, portal, state_code))

        # Deduplicate within the portal (JSON-LD + links can overlap).
        unique: dict[str, GrantRecord] = {}
        for record in records:
            unique.setdefault(record.dedupe_hash, record)
        return list(unique.values())

    # -- Orchestration ------------------------------------------------------

    async def run(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        state_codes: list[str] | None = None,
    ) -> SourceResult:
        result = SourceResult(source=SOURCE_NAME)
        codes = resolve_states(state_codes)
        if not codes:
            result.skipped = True
            result.skip_reason = "no matching state configs"
            return result

        owns_client = client is None
        client = client or build_client()

        jobs: list[tuple[str, dict[str, Any]]] = []
        for code in codes:
            config = load_state_config(code)
            if not config:
                result.record_error(f"{code}: state config missing")
                continue
            for portal in config.get("portals") or []:
                jobs.append((code, portal))

        if not jobs:
            result.skipped = True
            result.skip_reason = "no portals configured for the requested states"
            return result

        try:
            outcomes = await gather_limited(
                [(lambda c=code, p=portal: self.scrape_portal(client, p, c)) for code, portal in jobs],
                self.settings.states_max_concurrency,
            )

            failed = 0
            for (code, portal), records in zip(jobs, outcomes):
                if records is None:
                    failed += 1
                    result.record_error(f"{code}/{portal.get('name')}: scrape failed")
                    continue
                result.extend(records)

            result.state_breakdown = _breakdown(result.records, codes)
            logger.info(
                "state_local: %s records across %s states (%s/%s portals failed)",
                result.found,
                len({c for c in codes}),
                failed,
                len(jobs),
            )
        except Exception as exc:  # pragma: no cover - defensive
            result.record_error(f"unexpected failure: {exc}")
        finally:
            if owns_client:
                await client.aclose()

        return result


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _make_record(
    *,
    title: str,
    url: str | None,
    state_code: str,
    portal: dict[str, Any],
    deadline_raw: Any,
    amount_raw: Any,
    description: Any,
    external_id: str | None,
    raw: dict[str, Any],
) -> GrantRecord:
    return GrantRecord(
        title=strip_html(title),
        source=f"{SOURCE_STATE_PREFIX}{state_code}",
        external_id=external_id,
        agency=portal.get("name") or f"{state_code} state government",
        deadline=parse_deadline(deadline_raw),
        amount_min=None,
        amount_max=parse_amount(amount_raw),
        description=strip_html(description) if description else None,
        url=url,
        state_code=state_code,
        raw_json={**raw, "portal_name": portal.get("name"), "portal_url": portal.get("url")},
    )


def _iter_nodes(payload: Any, depth: int = 0):
    """Yield every schema.org node in a JSON-LD payload.

    JSON-LD nests opportunities in several ways - a bare object, a list, an
    ``@graph``, or an ``ItemList`` whose ``itemListElement`` holds the real
    nodes - so we walk all containers rather than guessing the shape.
    """
    if depth > 12:
        return
    if isinstance(payload, list):
        for item in payload:
            yield from _iter_nodes(item, depth + 1)
    elif isinstance(payload, dict):
        yield payload
        for key, value in payload.items():
            if key in _NODE_CONTAINER_KEYS:
                yield from _iter_nodes(value, depth + 1)


_NODE_CONTAINER_KEYS = {"@graph", "itemListElement", "item", "hasPart", "mainEntity", "about", "isPartOf"}


_UNWANTED_TYPES = {"Organization", "Website", "WebSite", "BreadcrumbList", "Person"}


def _record_from_jsonld(
    node: dict[str, Any], portal: dict[str, Any], state_code: str
) -> GrantRecord | None:
    node_type = str(node.get("@type") or "")
    if node_type in _UNWANTED_TYPES:
        return None
    title = node.get("name") or node.get("headline")
    if not isinstance(title, str) or len(title) < 12:
        return None
    keywords = [k.casefold() for k in portal.get("keywords") or []]
    if keywords and not any(k in title.casefold() for k in keywords):
        # Structured data still has to be grant-shaped.
        blob = f"{title} {node.get('description') or ''}".casefold()
        if not any(k in blob for k in keywords):
            return None

    url = node.get("url")
    offers = node.get("offers")
    amount_raw = node.get("amount")
    if amount_raw is None and isinstance(offers, dict):
        amount_raw = offers.get("price")
    return _make_record(
        title=title,
        url=urljoin(portal.get("url") or "", url) if url else portal.get("url"),
        state_code=state_code,
        portal=portal,
        deadline_raw=node.get("endDate") or node.get("deadline") or node.get("validThrough"),
        amount_raw=amount_raw,
        description=node.get("description"),
        external_id=str(node.get("@id") or url or title)[:255],
        raw=node,
    )


def _iter_dicts(payload: Any):
    if isinstance(payload, dict):
        yield payload
        for value in payload.values():
            yield from _iter_dicts(value)
    elif isinstance(payload, list):
        for item in payload:
            yield from _iter_dicts(item)


def _deadline_near(html: str, href: str) -> str | None:
    """Look for a date in the ~400 chars following the anchor."""
    idx = html.find(href)
    if idx < 0:
        return None
    window = strip_html(html[idx : idx + 900])
    match = re.search(
        r"(?:deadline|due|closes?|open until|applications? due)\s*[:\-]?\s*"
        r"([A-Za-z0-9 ,/.]{6,32})",
        window,
        re.I,
    )
    return match.group(1).strip() if match else None


def _amount_near(text: str) -> float | None:
    match = re.search(r"\$[\d,]+(?:\.\d+)?(?:\s*[KkMm])?", text)
    return parse_amount(match.group(0)) if match else None


def _breakdown(records: list[GrantRecord], codes: list[str]) -> dict[str, int]:
    counts = {code: 0 for code in codes}
    for record in records:
        if record.state_code:
            counts[record.state_code] = counts.get(record.state_code, 0) + 1
    return counts


async def fetch_state_local(state_codes: list[str] | None = None) -> SourceResult:
    return await StateLocalScraper().run(state_codes=state_codes)


__all__ = [
    "StateLocalScraper",
    "fetch_state_local",
    "resolve_states",
    "available_states",
    "load_state_config",
    "SOURCE_NAME",
]