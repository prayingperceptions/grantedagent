"""Generate hunter/states/*.json - one config per state and DC.

Each file describes where that state publishes its grant opportunities. The
schema is intentionally the same shape as a source config so a newly discovered
portal is a data change, not a code change:

    {
      "state_code": "WI",
      "state_name": "Wisconsin",
      "portals": [
        {"name": "...", "url": "...", "kind": "html", "selectors": {...},
         "keywords": [...], "mode": "http"}
      ]
    }

`mode` is ``http`` for statically served pages (fast) and ``playwright`` for
JS-rendered portals. Most state portals are JS apps behind a CDN, so entries
default to ``playwright`` and ``http`` is the optimisation.

Run this script to regenerate. It is idempotent and rewrites every file.
"""

from __future__ import annotations

import json
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parents[1] / "hunter" / "states"

STATE_NAMES: dict[str, str] = {
    "AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas",
    "CA": "California", "CO": "Colorado", "CT": "Connecticut", "DE": "Delaware",
    "DC": "District of Columbia", "FL": "Florida", "GA": "Georgia", "HI": "Hawaii",
    "ID": "Idaho", "IL": "Illinois", "IN": "Indiana", "IA": "Iowa",
    "KS": "Kansas", "KY": "Kentucky", "LA": "Louisiana", "ME": "Maine",
    "MD": "Maryland", "MA": "Massachusetts", "MI": "Michigan", "MN": "Minnesota",
    "MS": "Mississippi", "MO": "Missouri", "MT": "Montana", "NE": "Nebraska",
    "NV": "Nevada", "NH": "New Hampshire", "NJ": "New Jersey", "NM": "New Mexico",
    "NY": "New York", "NC": "North Carolina", "ND": "North Dakota", "OH": "Ohio",
    "OK": "Oklahoma", "OR": "Oregon", "PA": "Pennsylvania", "RI": "Rhode Island",
    "SC": "South Carolina", "SD": "South Dakota", "TN": "Tennessee", "TX": "Texas",
    "UT": "Utah", "VT": "Vermont", "VA": "Virginia", "WA": "Washington",
    "WV": "West Virginia", "WI": "Wisconsin", "WY": "Wyoming",
}

DEFAULT_KEYWORDS = [
    "grant", "grants", "funding", "rfp", "rfa", "request for proposals",
    "request for applications", "notice of funding", "nofo", "solicitation",
    "apply", "application", "award", "opportunity", "deadline",
]

DEFAULT_SELECTORS = {
    "item": "article, li, .grant, .card, tr",
    "title": "h1, h2, h3, h4, a",
    "link": "a[href]",
    "date": "time, .date, .deadline",
    "amount": ".amount, .funding, .award",
    "description": "p",
}

# Per-state portal seeds. Only URLs we verified reachable are marked
# "verified": true; the rest are best-known official portals and are probed at
# runtime, with failures recorded rather than fatal.
PORTALS: dict[str, list[dict]] = {
    "AL": [{"name": "Alabama Department of Finance Grants", "url": "https://www.alabama.gov/grants/", "mode": "playwright"}],
    "AK": [{"name": "Alaska Division of Community and Regional Affairs", "url": "https://www.commerce.alaska.gov/web/dcra/Grants.aspx", "mode": "playwright"}],
    "AZ": [{"name": "Arizona Grants Portal", "url": "https://grants.az.gov/", "mode": "playwright"}],
    "AR": [{"name": "Arkansas Grants", "url": "https://www.arkansas.gov/grants/", "mode": "playwright"}],
    "CA": [
        {"name": "California Grants Portal", "url": "https://www.grants.ca.gov/grants/", "mode": "playwright", "verified": True},
        {"name": "California Grants Portal Home", "url": "https://www.grants.ca.gov/", "mode": "playwright", "verified": True},
    ],
    "CO": [{"name": "Colorado Grants", "url": "https://www.colorado.gov/grants", "mode": "playwright"}],
    "CT": [{"name": "Connecticut Grants", "url": "https://portal.ct.gov/grants", "mode": "playwright"}],
    "DE": [{"name": "Delaware Grants", "url": "https://delaware.gov/grants/", "mode": "playwright"}],
    "DC": [{"name": "District of Columbia Grants", "url": "https://grants.dc.gov/", "mode": "playwright"}],
    "FL": [{"name": "Florida Grants", "url": "https://www.myfloridahouse.gov/grants", "mode": "playwright"}],
    "GA": [{"name": "Georgia Grants", "url": "https://grants.georgia.gov/", "mode": "playwright"}],
    "HI": [{"name": "Hawaii Grants", "url": "https://hawaii.gov/grants/", "mode": "playwright"}],
    "ID": [{"name": "Idaho Grants", "url": "https://grants.idaho.gov/", "mode": "playwright"}],
    "IL": [{"name": "Illinois Grants", "url": "https://www.illinois.gov/grants.html", "mode": "playwright"}],
    "IN": [{"name": "Indiana Grants", "url": "https://www.in.gov/grants/", "mode": "playwright"}],
    "IA": [{"name": "Iowa Grants", "url": "https://das.iowa.gov/state-procurement/grants", "mode": "playwright"}],
    "KS": [{"name": "Kansas Grants", "url": "https://www.kansas.gov/grants/", "mode": "playwright"}],
    "KY": [{"name": "Kentucky Grants", "url": "https://grants.ky.gov/", "mode": "playwright"}],
    "LA": [{"name": "Louisiana Grants", "url": "https://www.louisiana.gov/grants/", "mode": "playwright"}],
    "ME": [{"name": "Maine Grants", "url": "https://www.maine.gov/grants/", "mode": "playwright"}],
    "MD": [{"name": "Maryland Grants", "url": "https://grants.maryland.gov/", "mode": "playwright"}],
    "MA": [{"name": "Massachusetts Grants", "url": "https://www.mass.gov/grants", "mode": "playwright"}],
    "MI": [{"name": "Michigan Grants", "url": "https://www.michigan.gov/grants", "mode": "playwright"}],
    "MN": [
        {"name": "Minnesota Grants Management", "url": "https://mn.gov/admin/grants/", "mode": "playwright", "verified": True},
    ],
    "MS": [{"name": "Mississippi Grants", "url": "https://www.ms.gov/grants/", "mode": "playwright"}],
    "MO": [{"name": "Missouri Grants", "url": "https://www.mo.gov/grants/", "mode": "playwright"}],
    "MT": [{"name": "Montana Grants", "url": "https://mt.gov/grants/", "mode": "playwright"}],
    "NE": [{"name": "Nebraska Grants", "url": "https://nebraska.gov/grants/", "mode": "playwright"}],
    "NV": [{"name": "Nevada Grants", "url": "https://nv.gov/grants/", "mode": "playwright"}],
    "NH": [{"name": "New Hampshire Grants", "url": "https://www.nh.gov/grants/", "mode": "playwright"}],
    "NJ": [
        {"name": "New Jersey Grants", "url": "https://grants.nj.gov/", "mode": "playwright", "verified": True},
    ],
    "NM": [{"name": "New Mexico Grants", "url": "https://www.nm.gov/grants/", "mode": "playwright"}],
    "NY": [{"name": "New York State Grants", "url": "https://www.grants.ny.gov/", "mode": "playwright"}],
    "NC": [{"name": "North Carolina Grants", "url": "https://www.nc.gov/grants/", "mode": "playwright"}],
    "ND": [{"name": "North Dakota Grants", "url": "https://www.nd.gov/grants/", "mode": "playwright"}],
    "OH": [{"name": "Ohio Grants", "url": "https://grants.ohio.gov/", "mode": "playwright"}],
    "OK": [{"name": "Oklahoma Grants", "url": "https://oklahoma.gov/grants.html", "mode": "playwright"}],
    "OR": [{"name": "Oregon Grants", "url": "https://www.oregon.gov/grants/", "mode": "playwright"}],
    "PA": [
        {"name": "Pennsylvania Grants", "url": "https://www.pa.gov/grants", "mode": "playwright", "verified": True},
    ],
    "RI": [{"name": "Rhode Island Grants", "url": "https://www.ri.gov/grants/", "mode": "playwright"}],
    "SC": [{"name": "South Carolina Grants", "url": "https://www.sc.gov/grants", "mode": "playwright"}],
    "SD": [{"name": "South Dakota Grants", "url": "https://sd.gov/grants/", "mode": "playwright"}],
    "TN": [{"name": "Tennessee Grants", "url": "https://www.tn.gov/grants.html", "mode": "playwright"}],
    "TX": [{"name": "Texas Grants", "url": "https://www.texas.gov/grants/", "mode": "playwright"}],
    "UT": [{"name": "Utah Grants", "url": "https://grants.utah.gov/", "mode": "playwright"}],
    "VT": [{"name": "Vermont Grants", "url": "https://www.vermont.gov/grants", "mode": "playwright"}],
    "VA": [{"name": "Virginia Grants", "url": "https://grants.virginia.gov/", "mode": "playwright"}],
    "WA": [{"name": "Washington Grants", "url": "https://www.wa.gov/grants", "mode": "playwright"}],
    "WV": [{"name": "West Virginia Grants", "url": "https://www.wv.gov/grants/", "mode": "playwright"}],
    "WI": [
        {"name": "Wisconsin Humanities Grants", "url": "https://www.wisconsinhumanities.org/grants", "mode": "http", "verified": True},
        {"name": "UW System Grants and Awards", "url": "https://www.wisconsin.edu/grants-awards/", "mode": "http", "verified": True},
        {"name": "Wisconsin Department of Administration Grants", "url": "https://doa.wi.gov/Pages/Grants.aspx", "mode": "playwright"},
    ],
    "WY": [{"name": "Wyoming Grants", "url": "https://www.wyo.gov/grants", "mode": "playwright"}],
}


def build_state(code: str) -> dict:
    portals = []
    for portal in PORTALS.get(code, []):
        portals.append(
            {
                "name": portal["name"],
                "url": portal["url"],
                "mode": portal.get("mode", "playwright"),
                "verified": portal.get("verified", False),
                "selectors": DEFAULT_SELECTORS,
                "keywords": DEFAULT_KEYWORDS,
                "max_items": 60,
            }
        )
    if not portals:
        # Still emit a file so every state is accounted for in a nationwide run.
        portals.append(
            {
                "name": f"{STATE_NAMES[code]} state grants",
                "url": f"https://www.{code.lower()}.gov/grants",
                "mode": "playwright",
                "verified": False,
                "selectors": DEFAULT_SELECTORS,
                "keywords": DEFAULT_KEYWORDS,
                "max_items": 60,
            }
        )
    return {
        "state_code": code,
        "state_name": STATE_NAMES[code],
        "base_domain_suffix": ".gov",
        "portals": portals,
    }


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for code in STATE_NAMES:
        payload = build_state(code)
        path = OUT_DIR / f"{code.lower()}.json"
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    verified = sum(1 for p in PORTALS.values() for q in p if q.get("verified"))
    print(f"wrote {len(STATE_NAMES)} state configs to {OUT_DIR} ({verified} verified portals)")


if __name__ == "__main__":
    main()