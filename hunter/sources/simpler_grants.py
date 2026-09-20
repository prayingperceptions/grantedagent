"""Simpler Grants (HHS) - api.simpler.grants.gov.

Simpler Grants is a modern index over the same federal opportunities grants.gov
publishes, but its search endpoint returns richer synopsis text and supports
filtered/paged queries without a key *if* the deployment allows anonymous
reads. Every endpoint on the public host has returned 401 without a key, so the
source is key-gated: set ``SIMPLER_GRANTS_API_KEY`` and it activates, otherwise
it reports ``skipped`` and the run proceeds.

Both request shapes are supported because the service has shipped a GET list
and a POST ``/search``. POST is preferred; GET is the fallback.
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

logger = logging.getLogger("hunter.sources.simpler_grants")

SOURCE = SOURCE_FEDERAL
SOURCE_NAME = "simpler_grants"


class SimplerGrantsSource:
    name = SOURCE_NAME

    def __init__(self) -> None:
        self.settings = get_settings()

    @property
    def enabled(self) -> bool:
        return bool(self.settings.simpler_grants_api_key)

    def _headers(self) -> dict[str, str]:
        return {"X-Auth": self.settings.simpler_grants_api_key or ""}

    async def fetch_search_page(self, client: httpx.AsyncClient, page: int, size: int) -> dict | None:
        payload = {
            "pagination": {
                "page_offset": page,
                "page_size": size,
                "sort_order": [{"order_by": "post_date", "sort_direction": "descending"}],
            },
            "filters": {},
        }
        data = await request_json(
            client,
            "POST",
            f"{self.settings.simpler_grants_api}/opportunities/search",
            source=SOURCE_NAME,
            headers=self._headers(),
            json=payload,
        )
        if data is not None:
            return data

        # Fallback: GET list with query-string paging.
        fallback = await request_json(
            client,
            "GET",
            f"{self.settings.simpler_grants_api}/opportunities",
            source=SOURCE_NAME,
            headers=self._headers(),
            params={"page_offset": page, "page_size": size},
        )
        return fallback

    # -- Parsing ------------------------------------------------------------

    @staticmethod
    def parse_opportunity(item: dict[str, Any]) -> GrantRecord | None:
        """Map one Simpler opportunity payload to a GrantRecord.

        Simpler models amounts as ``{amount, amount_type}`` objects and may nest
        the summary under ``summary``.
        """
        opportunity = item.get("opportunity") or item
        title = strip_html(
            opportunity.get("opportunity_title")
            or opportunity.get("title")
            or item.get("title")
            or ""
        )
        if not title:
            return None

        opp_id = (
            opportunity.get("opportunity_id")
            or opportunity.get("id")
            or opportunity.get("opportunity_number")
        )

        agency = strip_html(
            opportunity.get("agency_name")
            or opportunity.get("agency")
            or opportunity.get("top_level_agency_name")
            or ""
        ) or None

        deadline = parse_deadline(
            opportunity.get("close_date")
            or opportunity.get("response_date")
            or item.get("close_date")
        )

        summary = item.get("summary") or {}
        description = strip_html(
            summary.get("summary_description")
            or opportunity.get("summary_description")
            or opportunity.get("description")
            or ""
        ) or None

        amount_min = None
        amount_max = None
        # award_floor / award_ceiling may be scalars or {amount,...} dicts.
        for raw, target in (
            (opportunity.get("award_floor"), "min"),
            (opportunity.get("award_ceiling"), "max"),
        ):
            parsed = _amount_from_obj(raw)
            if target == "min":
                amount_min = parsed
            else:
                amount_max = parsed

        url = opportunity.get("opportunity_url") or opportunity.get("link")
        if not url and opp_id:
            url = f"https://simpler.grants.gov/opportunity/{opp_id}"

        return GrantRecord(
            title=title,
            source=SOURCE,
            external_id=str(opp_id) if opp_id is not None else None,
            agency=agency,
            deadline=deadline,
            amount_min=amount_min,
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
            result.skip_reason = "SIMPLER_GRANTS_API_KEY not set"
            logger.info("simpler_grants skipped: no API key configured")
            return result

        owns_client = client is None
        client = client or build_client()
        size = self.settings.simpler_grants_page_size
        max_pages = self.settings.simpler_grants_max_pages
        seen: set[str] = set()

        try:
            for page in range(max_pages):
                payload = await self.fetch_search_page(client, page, size)
                if payload is None:
                    if page == 0:
                        result.record_error("Simpler Grants search failed (requires key or unreachable)")
                        return result
                    break

                data = payload.get("data") or {}
                items = data.get("data") or data.get("opportunities") or []
                if isinstance(items, dict):
                    items = items.get("opportunities") or []

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

                logger.info("simpler_grants page %s: %s records (%s total)", page + 1, len(items), result.found)

                pagination = data.get("pagination") or {}
                total_pages = pagination.get("total_pages")
                if isinstance(total_pages, int) and page + 1 >= total_pages:
                    break
                if len(items) < size:
                    break
        except Exception as exc:  # pragma: no cover - defensive
            result.record_error(f"unexpected failure: {exc}")
        finally:
            if owns_client:
                await client.aclose()

        return result


def _amount_from_obj(raw: Any) -> float | None:
    if raw is None:
        return None
    if isinstance(raw, dict):
        return parse_amount(raw.get("amount") or raw.get("value"))
    return parse_amount(raw)


async def fetch_simpler_grants() -> SourceResult:
    return await SimplerGrantsSource().run()


__all__ = ["SimplerGrantsSource", "fetch_simpler_grants", "SOURCE", "SOURCE_NAME"]