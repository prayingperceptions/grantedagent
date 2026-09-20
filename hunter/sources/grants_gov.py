"""grants.gov - every federal funding opportunity.

Uses the v1 JSON API (``search2``), which unlike the legacy XML feed returns
structured award ranges and dates and needs no API key. ``search2`` supports
``oppStatuses`` so one pass can pull both forecasted and posted opportunities.

Pagination is cursor-free: ``startRecordNum`` is an absolute offset, and the API
caps a page at 100 rows. We page until either the reported hit count is
consumed, an empty page arrives, or the ``max_pages`` budget is spent.

The search projection is missing amount fields on many synopses, so a bounded
number of detail lookups (``fetchOpportunity``) backfill amounts and the full
description for the top results. Detail calls are far more expensive than
search, hence the cap.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from hunter.config import get_settings
from hunter.sources.base import (
    SOURCE_FEDERAL,
    GrantRecord,
    SourceResult,
    build_client,
    parse_amount,
    parse_deadline,
    request_json,
    strip_html,
)

logger = logging.getLogger("hunter.sources.grants_gov")

SOURCE = SOURCE_FEDERAL
SOURCE_NAME = "grants_gov"

DETAIL_URL = "https://grants.gov/search-results-detail/{opportunity_id}"


class GrantsGovSource:
    name = SOURCE_NAME

    def __init__(self, *, max_detail_lookups: int = 0) -> None:
        self.settings = get_settings()
        self.max_detail_lookups = max_detail_lookups

    # -- HTTP ---------------------------------------------------------------

    async def fetch_page(self, client: httpx.AsyncClient, offset: int, rows: int) -> dict | None:
        payload = {
            "rows": rows,
            "startRecordNum": offset,
            "keyword": "",
            "oppStatuses": self.settings.grants_gov_statuses,
            "sortBy": "openDate|desc",
        }
        return await request_json(
            client,
            "POST",
            f"{self.settings.grants_gov_api}/search2",
            source=SOURCE_NAME,
            json=payload,
        )

    async def fetch_detail(self, client: httpx.AsyncClient, opportunity_id: str) -> dict | None:
        return await request_json(
            client,
            "POST",
            f"{self.settings.grants_gov_api}/fetchOpportunity",
            source=SOURCE_NAME,
            json={"opportunityId": int(opportunity_id)} if str(opportunity_id).isdigit() else {"opportunityId": opportunity_id},
            retries=2,
        )

    # -- Parsing ------------------------------------------------------------

    @staticmethod
    def parse_hit(hit: dict[str, Any]) -> GrantRecord | None:
        """Map a ``search2`` oppHit to a GrantRecord.

        ``search2`` returns ``openDate``/``closeDate`` as ``MM/DD/YYYY`` and
        carries the award range directly on the hit for most rows.
        """
        title = strip_html(hit.get("title") or "")
        if not title:
            return None

        opp_id = hit.get("id")
        number = hit.get("number") or hit.get("opportunityNumber")
        agency = strip_html(hit.get("agency") or "") or None

        deadline = parse_deadline(hit.get("closeDate"))
        if deadline is None:
            deadline = parse_deadline(hit.get("responseDate"))

        url = None
        if opp_id is not None:
            url = DETAIL_URL.format(opportunity_id=opp_id)
        elif number:
            url = f"https://www.grants.gov/search-results-detail?oppNum={number}"

        description = strip_html(hit.get("description") or hit.get("synopsis") or "") or None

        return GrantRecord(
            title=title,
            source=SOURCE,
            external_id=str(opp_id) if opp_id is not None else (str(number) if number else None),
            agency=agency,
            deadline=deadline,
            amount_min=parse_amount(hit.get("awardFloor")),
            amount_max=parse_amount(hit.get("awardCeiling")),
            description=description,
            url=url,
            state_code=None,
            raw_json=hit,
        )

    @staticmethod
    def apply_detail(record: GrantRecord, detail: dict[str, Any]) -> GrantRecord:
        """Backfill amounts/description from ``fetchOpportunity``."""
        data = detail.get("data") or {}
        synopsis = data.get("synopsis") or {}

        record.amount_min = record.amount_min or parse_amount(
            synopsis.get("awardFloor") or data.get("awardFloor")
        )
        record.amount_max = record.amount_max or parse_amount(
            synopsis.get("awardCeiling") or data.get("awardCeiling")
        )
        if not record.description:
            record.description = (
                strip_html(synopsis.get("synopsisDesc") or "") or None
            )
        if not record.agency:
            record.agency = strip_html(
                synopsis.get("agencyName") or (data.get("agencyDetails") or {}).get("agencyName") or ""
            ) or None
        if record.deadline is None:
            record.deadline = parse_deadline(
                synopsis.get("responseDate") or synopsis.get("closeDate")
            )
        record.raw_json = {**(record.raw_json or {}), "detail": data}
        return record

    # -- Orchestration ------------------------------------------------------

    async def run(self, *, client: httpx.AsyncClient | None = None) -> SourceResult:
        result = SourceResult(source=SOURCE_NAME)
        owns_client = client is None
        client = client or build_client()

        rows = self.settings.grants_gov_rows
        max_pages = self.settings.grants_gov_max_pages
        seen_ids: set[str] = set()
        hit_count: int | None = None

        try:
            for page in range(max_pages):
                offset = page * rows
                payload = await self.fetch_page(client, offset, rows)
                if payload is None:
                    if page == 0:
                        result.record_error("search2 request failed (no data returned)")
                        return result
                    break

                if payload.get("errorcode") not in (0, None):
                    result.record_error(str(payload.get("msg") or payload.get("errorcode")))
                    if page == 0:
                        return result
                    break

                data = payload.get("data") or {}
                if hit_count is None:
                    hit_count = data.get("hitCount")

                # The API has shipped both key names across revisions.
                hits = data.get("oppHits") or data.get("searchHits") or []
                if not hits:
                    break

                for hit in hits:
                    key = str(hit.get("id") or hit.get("number") or hit.get("title"))
                    if key in seen_ids:
                        continue
                    seen_ids.add(key)
                    record = self.parse_hit(hit)
                    if record is not None:
                        result.records.append(record)

                logger.info(
                    "grants.gov page %s: +%s records (%s total, hitCount=%s)",
                    page + 1,
                    len(hits),
                    result.found,
                    hit_count,
                )

                if len(hits) < rows:
                    break
                if hit_count is not None and offset + len(hits) >= hit_count:
                    break

            if self.max_detail_lookups > 0 and result.records:
                await self._backfill_details(client, result)
        except Exception as exc:  # pragma: no cover - defensive
            result.record_error(f"unexpected failure: {exc}")
        finally:
            if owns_client:
                await client.aclose()

        return result

    async def _backfill_details(self, client: httpx.AsyncClient, result: SourceResult) -> None:
        """Enrich records that are missing an amount or description."""
        candidates = [
            r
            for r in result.records
            if r.external_id and (r.amount_max is None or not r.description)
        ][: self.max_detail_lookups]

        for record in candidates:
            detail = await self.fetch_detail(client, record.external_id)  # type: ignore[arg-type]
            if detail:
                self.apply_detail(record, detail)


async def fetch_grants(*, max_detail_lookups: int = 0) -> SourceResult:
    """Convenience entry point used by the scheduler and CLI."""
    return await GrantsGovSource(max_detail_lookups=max_detail_lookups).run()


__all__ = ["GrantsGovSource", "fetch_grants", "SOURCE", "SOURCE_NAME"]