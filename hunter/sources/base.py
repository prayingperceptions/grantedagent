"""Shared plumbing for every Hunter source.

Design notes that matter:

* ``GrantRecord`` is the wire format between sources and the DB writer. Sources
  never touch SQLAlchemy, so they stay unit-testable without a database.
* Sources degrade instead of exploding. A dead foundation feed, an expired API
  key, or a state portal that redesigned its HTML yields a ``SourceError`` in
  ``SourceResult.errors`` and the run continues. A nationwide crawl must never
  fail because one of 200 funders is down.
* Blocking libraries (feedparser, Playwright sync API) are pushed to a worker
  thread. APScheduler runs a synchronous job, and Playwright's sync API refuses
  to run inside a live asyncio loop, so the async orchestration lives here and
  the sync entry point is ``run_async``.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Iterable, TypeVar
from urllib.parse import urlparse

import httpx
from dateutil import parser as dateparser

from hunter.config import get_settings
from hunter.deduper import dedupe_hash
from hunter.models import (
    SOURCE_FEDERAL,
    SOURCE_NATIONAL_FOUNDATION,
    SOURCE_STATE_PREFIX,
)

logger = logging.getLogger("hunter.sources")

T = TypeVar("T")

DEFAULT_RETRY_STATUS = {408, 425, 429, 500, 502, 503, 504}


class SourceError(Exception):
    """Raised for a recoverable per-source failure (recorded, not fatal)."""

    def __init__(self, source: str, message: str) -> None:
        super().__init__(f"[{source}] {message}")
        self.source = source
        self.message = message


@dataclass(slots=True)
class GrantRecord:
    """One normalized grant opportunity."""

    title: str
    source: str
    external_id: str | None = None
    agency: str | None = None
    deadline: date | None = None
    amount_min: float | None = None
    amount_max: float | None = None
    description: str | None = None
    url: str | None = None
    state_code: str | None = None
    raw_json: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        self.title = (self.title or "").strip()
        if self.agency:
            self.agency = self.agency.strip()
        if self.description:
            self.description = _collapse(self.description)

    @property
    def dedupe_hash(self) -> str:
        return dedupe_hash(self.title, self.agency, self.deadline)

    def to_row(self) -> dict[str, Any]:
        return {
            "external_id": _clip(self.external_id, 255),
            "title": self.title or "Untitled opportunity",
            "agency": self.agency,
            "deadline": self.deadline,
            "amount_min": self.amount_min,
            "amount_max": self.amount_max,
            "description": self.description,
            "url": self.url,
            "raw_json": self.raw_json,
            "source": self.source,
            "state_code": self.state_code,
            "dedupe_hash": self.dedupe_hash,
        }


@dataclass
class SourceResult:
    """Outcome of one source run."""

    source: str
    records: list[GrantRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str | None = None
    state_breakdown: dict[str, int] = field(default_factory=dict)

    @property
    def found(self) -> int:
        return len(self.records)

    @property
    def ok(self) -> bool:
        return not self.errors

    def extend(self, records: Iterable[GrantRecord]) -> None:
        self.records.extend(records)

    def record_error(self, message: str) -> None:
        self.errors.append(message)
        logger.warning("[%s] %s", self.source, message)

    def __add__(self, other: "SourceResult") -> "SourceResult":
        merged = SourceResult(source=f"{self.source}+{other.source}")
        merged.records = self.records + other.records
        merged.errors = self.errors + other.errors
        merged.skipped = self.skipped and other.skipped
        merged.state_breakdown = dict(self.state_breakdown)
        for code, count in other.state_breakdown.items():
            merged.state_breakdown[code] = merged.state_breakdown.get(code, 0) + count
        return merged


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------


def build_client(**overrides: Any) -> httpx.AsyncClient:
    """An AsyncClient with sane retries and a contactable User-Agent.

    grants.gov and several state portals reject clients without a UA, and the
    default httpx UA is a common cause of silent empty responses.
    """
    settings = overrides.pop("settings", None) or get_settings()
    headers = {
        "User-Agent": settings.user_agent,
        "Accept": "application/json, application/xml, text/html;q=0.9, */*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    headers.update(overrides.pop("headers", {}) or {})
    transport = httpx.AsyncHTTPTransport(retries=3)
    return httpx.AsyncClient(
        headers=headers,
        timeout=httpx.Timeout(settings.http_timeout_s, connect=10.0),
        follow_redirects=True,
        transport=transport,
        **overrides,
    )


async def request_json(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    source: str,
    retries: int = 3,
    backoff: float = 1.5,
    acceptable: set[int] | None = None,
    **kwargs: Any,
) -> Any:
    """JSON request with bounded exponential backoff.

    Returns ``None`` (never raises) when the endpoint is unreachable or returns
    a non-acceptable status, so callers can treat "no data" and "no access"
    identically. The final HTTP status is logged for triage.
    """
    acceptable = acceptable or {200}
    last_status: int | None = None
    for attempt in range(1, retries + 1):
        try:
            resp = await client.request(method, url, **kwargs)
            last_status = resp.status_code
            if resp.status_code in acceptable:
                try:
                    return resp.json()
                except ValueError:
                    logger.warning("[%s] non-JSON body from %s", source, url)
                    return None
            if resp.status_code in {401, 403}:
                logger.info("[%s] %s requires credentials (HTTP %s)", source, url, resp.status_code)
                return None
            if resp.status_code in {404, 400, 422}:
                logger.info("[%s] %s rejected request (HTTP %s)", source, url, resp.status_code)
                return None
            if resp.status_code in DEFAULT_RETRY_STATUS and attempt < retries:
                await asyncio.sleep(backoff * attempt)
                continue
            logger.warning("[%s] HTTP %s from %s", source, resp.status_code, url)
            return None
        except (httpx.TransportError, httpx.TimeoutException) as exc:
            if attempt == retries:
                logger.warning("[%s] %s unreachable: %s", source, url, exc)
                return None
            await asyncio.sleep(backoff * attempt)
    logger.warning("[%s] exhausted retries (%s) for %s", source, last_status, url)
    return None


async def request_text(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    source: str,
    retries: int = 2,
    **kwargs: Any,
) -> str | None:
    for attempt in range(1, retries + 1):
        try:
            resp = await client.request(method, url, **kwargs)
            if resp.status_code == 200:
                return resp.text
            if resp.status_code in {401, 403, 404, 410}:
                return None
            if resp.status_code in DEFAULT_RETRY_STATUS and attempt < retries:
                await asyncio.sleep(1.0 * attempt)
                continue
            return None
        except (httpx.TransportError, httpx.TimeoutException):
            if attempt == retries:
                return None
            await asyncio.sleep(1.0 * attempt)
    return None


# --------------------------------------------------------------------------
# Playwright (sync API inside a worker thread)
# --------------------------------------------------------------------------


def _playwright_fetch_sync(
    url: str,
    *,
    wait_for: str | None,
    wait_ms: int,
    timeout_ms: int,
    user_agent: str,
    scroll: bool,
) -> str | None:
    """Render one URL. Runs in a worker thread; must never see a live loop."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        try:
            context = browser.new_context(user_agent=user_agent, locale="en-US")
            page = context.new_page()
            page.route(
                re.compile(r"\.(png|jpe?g|gif|svg|woff2?|ttf|mp4|webm)(\?.*)?$"),
                lambda route: route.abort(),
            )
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            if wait_for:
                try:
                    page.wait_for_selector(wait_for, timeout=timeout_ms)
                except Exception:
                    logger.debug("wait_for_selector timeout for %s", url)
            if scroll:
                for _ in range(3):
                    page.mouse.wheel(0, 4000)
                    page.wait_for_timeout(400)
            page.wait_for_timeout(wait_ms)
            html = page.content()
            context.close()
            return html
        finally:
            browser.close()


async def playwright_fetch(
    url: str,
    *,
    wait_for: str | None = None,
    wait_ms: int = 750,
    timeout_ms: int = 25000,
    scroll: bool = False,
) -> str | None:
    """Async wrapper around the sync Playwright API."""
    settings = get_settings()
    try:
        return await asyncio.to_thread(
            _playwright_fetch_sync,
            url,
            wait_for=wait_for,
            wait_ms=wait_ms,
            timeout_ms=timeout_ms,
            user_agent=settings.user_agent,
            scroll=scroll,
        )
    except Exception as exc:  # browser missing, nav timeout, crash
        logger.warning("playwright fetch failed for %s: %s", url, exc)
        return None


async def gather_limited(
    tasks: list[Callable[[], Awaitable[T]]],
    limit: int,
) -> list[T | None]:
    """Run awaitables with a concurrency cap, preserving input order."""
    semaphore = asyncio.Semaphore(max(1, limit))

    async def _run(factory: Callable[[], Awaitable[T]]) -> T | None:
        async with semaphore:
            try:
                return await factory()
            except Exception as exc:  # one bad source must not sink the batch
                logger.warning("source task failed: %s", exc)
                return None

    return list(await asyncio.gather(*(_run(f) for f in tasks)))


def run_async(coro: Awaitable[T]) -> T:
    """Run a coroutine from sync code (APScheduler jobs, CLI, tests)."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)  # type: ignore[arg-type]

    # Already inside a loop (notebook / pytest-asyncio): use a private thread.
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(coro)).result()  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------

_WS_RE = re.compile(r"\s+")
_TAG_RE = re.compile(r"<[^>]+>")
_ENTITIES = {
    "&amp;": "&",
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&#39;": "'",
    "&apos;": "'",
    "&nbsp;": " ",
}


def strip_html(value: str | None) -> str:
    if not value:
        return ""
    text = _TAG_RE.sub(" ", value)
    for entity, char in _ENTITIES.items():
        text = text.replace(entity, char)
    return _collapse(text)


def _collapse(value: str) -> str:
    return _WS_RE.sub(" ", value).strip()


def _clip(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    return value[:limit]


_MONEY_RE = re.compile(r"([\d][\d,]*(?:\.\d+)?)\s*([KkMmBb])?")


def parse_amount(value: Any) -> float | None:
    """Parse ``$50,000``, ``50000``, ``1.2M``, ``250K`` into a float."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value) if value else None

    text = strip_html(str(value))
    if not text:
        return None
    if text.strip().lower() in {"n/a", "na", "none", "not specified", "-", "tbd"}:
        return None

    match = _MONEY_RE.search(text)
    if not match:
        return None
    number = float(match.group(1).replace(",", ""))
    suffix = (match.group(2) or "").lower()
    multiplier = {"k": 1_000, "m": 1_000_000, "b": 1_000_000_000}.get(suffix, 1)
    return number * multiplier


_DATE_FORMATS = (
    "%m/%d/%Y",
    "%Y-%m-%d",
    "%m-%d-%Y",
    "%m/%d/%y",
    "%B %d, %Y",
    "%b %d, %Y",
    "%B %d %Y",
    "%b %d %Y",
    "%d %B %Y",
    "%d %b %Y",
    "%Y-%m-%dT%H:%M:%S",
)

_DATE_ONLY_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


def parse_deadline(value: Any) -> date | None:
    """Best-effort date extraction from the many formats grant portals emit."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value

    text = strip_html(str(value))
    if not text:
        return None
    lowered = text.lower()
    if any(token in lowered for token in ("rolling", "ongoing", "no deadline", "continuous")):
        return None

    # Normalise the frequent ISO-ish shapes before handing off to dateutil.
    iso = _DATE_ONLY_RE.search(text)
    if iso and "T" not in text:
        try:
            return datetime.strptime(iso.group(0), "%Y-%m-%d").date()
        except ValueError:
            pass

    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text[: len(fmt) + 6].strip(), fmt).date()
        except ValueError:
            continue

    # dateutil handles "October 15, 2026 5:00 PM ET" and RFC-2822 feed dates.
    try:
        parsed = dateparser.parse(text, fuzzy=True)
    except (ValueError, OverflowError):
        return None
    if not parsed:
        return None
    today = datetime.now(timezone.utc).date()
    # A "deadline" decades in the past is almost always body text, not a date field.
    if parsed.date().year < 1990 or parsed.date().year > today.year + 30:
        return None
    return parsed.date()


def is_future(deadline: date | None, *, grace_days: int = 0) -> bool:
    """True when a deadline has not yet passed (rolling/None counts as open)."""
    if deadline is None:
        return True
    cutoff = datetime.now(timezone.utc).date() - timedelta(days=grace_days)
    return deadline >= cutoff


def registrable_domain(host: str) -> str:
    """Approximate eTLD+1. Correct for .gov/.us/.org/.com, which is all we see."""
    host = host.split(":")[0].lower().lstrip(".")
    if host.startswith("www."):
        host = host[4:]
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def same_site(candidate_url: str, base_url: str) -> bool:
    """True when candidate shares a registrable domain with base."""
    base = registrable_domain(urlparse(base_url).netloc) if base_url else ""
    if not base:
        return True
    return registrable_domain(urlparse(candidate_url).netloc) == base


__all__ = [
    "GrantRecord",
    "SourceResult",
    "SourceError",
    "build_client",
    "request_json",
    "request_text",
    "playwright_fetch",
    "gather_limited",
    "run_async",
    "strip_html",
    "parse_amount",
    "parse_deadline",
    "is_future",
    "registrable_domain",
    "same_site",
    "SOURCE_FEDERAL",
    "SOURCE_NATIONAL_FOUNDATION",
    "SOURCE_STATE_PREFIX",
]