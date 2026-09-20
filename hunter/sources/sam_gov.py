"""SAM.gov contract opportunities (FBO successor).

SAM.gov's ``/opportunities/v2/search`` is key-gated: requests without a valid
``api_key`` return an error rather than data, and the host is not reachable from
every network. Like Simpler Grants, this source self-disables when
``SAM_GOV_API_KEY`` is unset so an unconfigured deployment still completes.

The API requires ``postedFrom``/``postedTo`` (MM/DD/YYYY) and caps the date
window at one year, so the default window is the trailing 30 days. Each record
carries ``award`` (an ``{amount, ...}`` object) for the estimated value.
"""

from __future__ import annotations

import logging
from datetime import date, timedelta
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

logger = logging.getLogger("hunter.sources.sam_gov")

SOURCE = SOURCE_FEDERAL
SOURCE_NAME = "sam_gov"

PAGE_LIMIT = 100  # SAM.gov hard cap per page


class SamGovSource:
    name = SOURCE_NAME

    def __init__(self, *, lookback_days: int = 30) -> None:
        self.settings = get_settings()
        self.lookback_days = lookback_days

    @property
    def enabled(self) -> bool:
        return bool(self.settings.sam_gov_api_key)

    async def fetch_page(
        self,
        client: httpx.AsyncClient,
        offset: int,
        limit: int,
        posted_from: str,
        posted_to: str,
    ) -> dict | None:
        params = {
            "api_key": self.settings.sam_gov_api_key,
            "limit": limit,
            "offset": offset,
            "postedFrom": posted_from,
            "postedTo": posted_to,
            "active": "true",
        }
        return await request_json(
            client,
            "GET",
            f"{self.settings.sam_gov_api}/search",
            source=SOURCE_NAME,
            params=params,
        )

    # -- Parsing ------------------------------------------------------------

    @staticmethod
    def parse_opportunity(item: dict[str, Any]) -> GrantRecord | None:
        title = strip_html(item.get("title") or "")
        if not title:
            return None

        opp_id = item.get("noticeId") or item.get("solicitationNumber") or item.get("_id")
        agency = strip_html(
            item.get("fullParentPathName")
            or item.get("organizationHierarchy", [{}])[-1].get("name")
            or item.get("department")
            or ""
        ) or None

        # SAM "responseDeadLine" is an ISO timestamp; date is enough for us.
        deadline = parse_deadline(item.get("responseDeadLine"))

        award = item.get("award") or {}
        amount_max = parse_amount(award.get("amount")) if isinstance(award, dict) else None

        url = None
        if opp_id:
            url = f"https://sam.gov/opp/{opp_id}/view"

        description = strip_html(
            item.get("description") or item.get("solicitationDescription") or ""
        ) or None

        return GrantRecord(
            title=title,
            source=SOURCE,
            external_id=str(opp_id) if opp_id else None,
            agency=agency,
            deadline=deadline,
            amount_min=None,
            amount_max=amount_max,
            description=description,
            url=url,
            state_code=None,
            raw_json=item,
        )

    # -- Orchestration ------------------------------------------------------

    async def run(self, *, client: httpx.AsyncClient | None = None) -> SourceResult:
        result = SourceResult(source=SOURCE_NAME)
        if not self.enabled:
            result.skipped = True
            result.skip_reason = "SAM_GOV_API_KEY not set"
            logger.info("sam_gov skipped: no API key configured")
            return result

        owns_client = client is None
        client = client or build_client()

        today = date.today()
        posted_to = today.strftime("%m/%d/%Y")
        posted_from = (today - timedelta(days=self.lookback_days)).strftime("%m/%d/%Y")

        seen: set[str] = set()
        try:
            for page in range(self.settings.sam_gov_max_pages):
                offset = page * PAGE_LIMIT
                payload = await self.fetch_page(
                    client, offset, PAGE_LIMIT, posted_from, posted_to
                )
                if payload is None:
                    if page == 0:
                        result.record_error("SAM.gov opportunities request failed (key/host)")
                        return result
                    break

                items = payload.get("opportunitiesData") or payload.get("data") or []
                if not items:
                    break

                for item in items:
                    record = self.parse_opportunity(item)
                    if record is None:
                        continue
                    key = record.external_id or record.title
                    if key in seen:
                        continue
                    seen.add(key)
                    result.records.append(record)

                total = payload.get("totalRecords")
                logger.info(
                    "sam_gov page %s: %s records (%s total, totalRecords=%s)",
                    page + 1,
                    len(items),
                    result.found,
                    total,
                )

                if len(items) < PAGE_LIMIT:
                    break
                if isinstance(total, int) and offset + len(items) >= total:
                    break
        except Exception as exc:  # pragma: no cover - defensive
            result.record_error(f"unexpected failure: {exc}")
        finally:
            if owns_client:
                await client.aclose()

        return result


async def fetch_sam_gov() -> SourceResult:
    return await SamGovSource().run()


__all__ = ["SamGovSource", "fetch_sam_gov", "SOURCE", "SOURCE_NAME"]