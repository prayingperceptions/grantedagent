"""Generate hunter/data/foundations_registry.json.

The registry is data, not code, so it is generated once and committed. This
script exists so the list is auditable and regenerable.

Two tiers of entries:

* ``rss`` - the funder publishes a feed we verified responds with items. These
  are polled first.
* ``scrape`` - the funder has no feed (or none we verified); the URL is handed
  to Playwright and generic listing heuristics are applied.

Every entry carries ``state_code`` (``None`` == US-wide) so a state-scoped run
can pre-filter funders before touching the network.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

OUT = Path(__file__).resolve().parents[1] / "hunter" / "data" / "foundations_registry.json"

# Funders with a feed we actually fetched and found <item> entries in.
VERIFIED_RSS: list[tuple[str, str, str, str | None]] = [
    # (name, domain, feed_url, state_code)
    ("Robert Wood Johnson Foundation", "rwjf.org", "https://www.rwjf.org/en/rss.html", None),
    ("KFF (Kaiser Family Foundation)", "kff.org", "https://www.kff.org/feed/", None),
    ("The William and Flora Hewlett Foundation", "hewlett.org", "https://www.hewlett.org/feed/", None),
    ("The David and Lucile Packard Foundation", "packard.org", "https://www.packard.org/feed/", None),
    ("Carnegie Corporation of New York", "carnegie.org", "https://www.carnegie.org/feed/", None),
    ("Ford Foundation", "fordfoundation.org", "https://www.fordfoundation.org/feed/", None),
    ("The Rockefeller Foundation", "rockefellerfoundation.org", "https://www.rockefellerfoundation.org/feed/", None),
    ("John S. and James L. Knight Foundation", "knightfoundation.org", "https://knightfoundation.org/feed/", None),
    ("The Commonwealth Fund", "commonwealthfund.org", "https://www.commonwealthfund.org/rss.xml", None),
    ("The James Irvine Foundation", "irvine.org", "https://www.irvine.org/feed/", "CA"),
    ("The Bush Foundation", "bushfoundation.org", "https://www.bushfoundation.org/feed/", "MN"),
    ("Surdna Foundation", "surdna.org", "https://www.surdna.org/feed/", None),
    ("Health Forward Foundation", "healthforward.org", "https://www.healthforward.org/feed/", "MO"),
    ("The California Endowment", "calendow.org", "https://www.calendow.org/feed/", "CA"),
    ("New York Health Foundation", "nyhealthfoundation.org", "https://www.nyhealthfoundation.org/feed/", "NY"),
]

# Real US funders. website is the grant/news landing page; feed_url is left
# empty when we did not verify a feed, which routes them to the scraper.
FUNDERS: list[tuple[str, str, str | None, str, str]] = [
    # (name, domain, state_code, type, path)
    # --- Large national private foundations ---
    ("Bill & Melinda Gates Foundation", "gatesfoundation.org", None, "private", "/about/our-work"),
    ("The Eli and Edythe Broad Foundation", "broadfoundation.org", None, "private", "/"),
    ("The Andrew W. Mellon Foundation", "mellon.org", None, "private", "/grants"),
    ("The Alfred P. Sloan Foundation", "sloan.org", None, "private", "/programs"),
    ("The John D. and Catherine T. MacArthur Foundation", "macfound.org", None, "private", "/grants"),
    ("The Wallace H. Coulter Foundation", "coulterfoundation.org", None, "private", "/"),
    ("The Kresge Foundation", "kresge.org", None, "private", "/programs"),
    ("The Annie E. Casey Foundation", "aecf.org", None, "private", "/grants"),
    ("The Robert A. Welch Foundation", "welch1.org", None, "private", "/grant-programs"),
    ("The Simons Foundation", "simonsfoundation.org", None, "private", "/funding"),
    ("The Gordon and Betty Moore Foundation", "moore.org", None, "private", "/funding"),
    ("The Bloomberg Family Foundation", "bloomberg.org", None, "private", "/philanthropies"),
    ("The Walton Family Foundation", "waltonfamilyfoundation.org", None, "private", "/our-work"),
    ("The McKnight Foundation", "mcknight.org", "MN", "private", "/grants"),
    ("The McKnight Endowment Fund for Neuroscience", "mcknightfoundation.org", "MN", "private", "/"),
    ("The Joyce Foundation", "joycefdn.org", None, "private", "/grants"),
    ("The Spencer Foundation", "spencer.org", None, "private", "/grants"),
    ("The Russell Sage Foundation", "russellsage.org", None, "private", "/funding"),
    ("The William T. Grant Foundation", "wtgrantfoundation.org", None, "private", "/funding-opportunities"),
    ("The Doris Duke Charitable Foundation", "dorisduke.org", None, "private", "/grants"),
    ("The Duke Endowment", "dukeendowment.org", None, "private", "/grants"),
    ("The Z. Smith Reynolds Foundation", "zsmithreynolds.org", "NC", "private", "/grants"),
    ("The Mary Reynolds Babcock Foundation", "mrbf.org", None, "private", "/grants"),
    ("The Nathan Cummings Foundation", "nathancummings.org", None, "private", "/grants"),
    ("The Jessie Ball duPont Fund", "dupontfund.org", None, "private", "/grants"),
    ("The Bush Foundation Grants", "bushfoundation.org", None, "private", "/grants"),
    ("The Moody Foundation", "moodyf.org", "TX", "private", "/grants"),
    ("The Meadows Foundation", "mfi.org", "TX", "private", "/grants"),
    ("The Houston Endowment", "houstonendowment.org", "TX", "private", "/grants"),
    ("The Anne T. and Robert M. Bass Foundation", "bassfoundation.org", "TX", "private", "/"),
    ("The Pew Charitable Trusts", "pewtrusts.org", None, "private", "/projects"),
    ("The Arthur Vining Davis Foundations", "avdf.org", None, "private", "/grants"),
    ("The Henry Luce Foundation", "hluce.org", None, "private", "/grants"),
    ("The Carnegie Foundation for the Advancement of Teaching", "carnegiefoundation.org", None, "private", "/"),
    ("The W. K. Kellogg Foundation", "wkkf.org", None, "private", "/grants"),
    ("The Skillman Foundation", "skillman.org", "MI", "private", "/grants"),
    ("The Charles Stewart Mott Foundation", "mott.org", "MI", "private", "/grants"),
    ("The Frey Foundation", "freyfoundation.org", "MI", "private", "/grants"),
    ("The Kalamazoo Community Foundation", "kalfound.org", "MI", "community", "/grants"),
    ("The Battle Creek Community Foundation", "bccfoundation.org", "MI", "community", "/grants"),
    ("The McKnight Foundation of Michigan", "mcknightmichigan.org", "MI", "private", "/"),
    ("The Rockefeller Brothers Fund", "rbf.org", None, "private", "/grants"),
    ("The Ruth Mott Foundation", "ruthmott.org", "MI", "private", "/grants"),
    ("The Geraldine R. Dodge Foundation", "grdodge.org", "NJ", "private", "/grants"),
    ("The Victoria Foundation", "victoriafoundation.org", "NJ", "private", "/grants"),
    ("The Robert Wood Johnson Foundation Local", "rwjf.org", None, "private", "/en/grants"),
    ("The Helmsley Charitable Trust", "helmsleytrust.org", None, "private", "/grants"),
    ("The Blue Meridian Partners", "bluemeridian.org", None, "private", "/"),
    ("The Ballmer Group", "ballmergroup.org", None, "private", "/"),
    ("The Chan Zuckerberg Initiative", "chanzuckerberg.com", None, "private", "/"),
    ("The Emerson Collective", "emersoncollective.com", None, "private", "/"),
    ("The Bezos Family Foundation", "bezosfamilyfoundation.org", None, "private", "/"),
    ("The Bezos Earth Fund", "bezosearthfund.org", None, "private", "/grants"),
    ("The Open Society Foundations", "opensocietyfoundations.org", None, "private", "/grants"),
    ("The Ford Foundation International", "fordfoundation.org", None, "private", "/grants"),
    ("The Christensen Fund", "christensenfund.org", None, "private", "/grants"),
    ("The Barr Foundation", "barrfoundation.org", "MA", "private", "/grants"),
    ("The Boston Foundation", "tbf.org", "MA", "community", "/grants"),
    ("The Hyams Foundation", "hyamsfoundation.org", "MA", "private", "/grants"),
    ("The Klarman Family Foundation", "klarmanfamilyfoundation.org", "MA", "private", "/"),
    ("The Nellie Mae Education Foundation", "nmefoundation.org", "MA", "private", "/grants"),
    ("The Rhode Island Foundation", "rifoundation.org", "RI", "community", "/grants"),
    ("The Hartford Foundation for Public Giving", "hfpg.org", "CT", "community", "/grants"),
    ("The Community Foundation for Greater New Haven", "cfgnh.org", "CT", "community", "/grants"),
    ("The Melville Charitable Trust", "melvilletrust.org", None, "private", "/grants"),
    ("The New York Community Trust", "nycommunitytrust.org", "NY", "community", "/grants"),
    ("The New York Foundation", "nyf.org", "NY", "private", "/grants"),
    ("The Altman Foundation", "altmanfoundation.org", "NY", "private", "/grants"),
    ("The Robin Hood Foundation", "robinhood.org", "NY", "private", "/grants"),
    ("The Carnegie Corporation Grants", "carnegie.org", "NY", "private", "/grants"),
    ("The Staten Island Foundation", "thestatenislandfoundation.org", "NY", "community", "/grants"),
    ("The Long Island Community Foundation", "licf.org", "NY", "community", "/grants"),
    ("The Westchester Community Foundation", "wcf-ny.org", "NY", "community", "/grants"),
    ("The Rochester Area Community Foundation", "racf.org", "NY", "community", "/grants"),
    ("The Community Foundation for the Greater Capital Region", "cfgcr.org", "NY", "community", "/grants"),
    ("The Central New York Community Foundation", "cnycf.org", "NY", "community", "/grants"),
    ("The Philadelphia Foundation", "philafound.org", "PA", "community", "/grants"),
    ("The William Penn Foundation", "williampennfoundation.org", "PA", "private", "/grants"),
    ("The Heinz Endowments", "heinz.org", "PA", "private", "/grants"),
    ("The Richard King Mellon Foundation", "rkmf.org", "PA", "private", "/grants"),
    ("The Pittsburgh Foundation", "pittsburghfoundation.org", "PA", "community", "/grants"),
    ("The Scranton Area Community Foundation", "safdn.org", "PA", "community", "/grants"),
    ("The Lehigh Valley Community Foundation", "lvcf.org", "PA", "community", "/grants"),
    ("The Berks County Community Foundation", "bccf.org", "PA", "community", "/grants"),
    ("The Delaware Community Foundation", "delcf.org", "DE", "community", "/grants"),
    ("The Maryland Community Foundation", "cfmd.org", "MD", "community", "/grants"),
    ("The Abell Foundation", "abell.org", "MD", "private", "/grants"),
    ("The Annie E. Casey Foundation Baltimore", "aecf.org", "MD", "private", "/grants"),
    ("The Harry and Jeanette Weinberg Foundation", "hjweinbergfoundation.org", "MD", "private", "/grants"),
    ("The Meyer Foundation", "meyerfoundation.org", "DC", "private", "/grants"),
    ("The Greater Washington Community Foundation", "thecommunityfoundation.org", "DC", "community", "/grants"),
    ("The Caplin Foundation", "caplinfoundation.org", "DC", "private", "/"),
    ("The Community Foundation for Northern Virginia", "cfnova.org", "VA", "community", "/grants"),
    ("The Community Foundation of Greater Richmond", "cfrichmond.org", "VA", "community", "/grants"),
    ("The Hampton Roads Community Foundation", "hamptonroadscf.org", "VA", "community", "/grants"),
    ("The Cameron Foundation", "cameronfoundation.org", "VA", "private", "/grants"),
    ("The Danville Regional Foundation", "drfoundation.org", "VA", "private", "/grants"),
    ("The Kate B. Reynolds Charitable Trust", "kbr.org", "NC", "private", "/grants"),
    ("The Duke Endowment Grants", "dukeendowment.org", "NC", "private", "/how-we-help"),
    ("The Foundation For The Carolinas", "fftc.org", "NC", "community", "/grants"),
    ("The Community Foundation of Greater Greensboro", "cfgg.org", "NC", "community", "/grants"),
    ("The Triangle Community Foundation", "trianglecf.org", "NC", "community", "/grants"),
    ("The Coastal Community Foundation", "coastalcommunityfoundation.org", "SC", "community", "/grants"),
    ("The Central Carolina Community Foundation", "yourfoundation.org", "SC", "community", "/grants"),
    ("The Spartanburg County Foundation", "spcf.org", "SC", "community", "/grants"),
    ("The Gaylord and Dorothy Donnelley Foundation", "gddf.org", "IL", "private", "/grants"),
    ("The Chicago Community Trust", "cct.org", "IL", "community", "/grants"),
    ("The Joyce Foundation Chicago", "joycefdn.org", "IL", "private", "/grants"),
    ("The Polk Bros. Foundation", "polkbrosfdn.org", "IL", "private", "/grants"),
    ("The Crown Family Philanthropies", "crownfamilyphilanthropies.org", "IL", "private", "/"),
    ("The Lloyd A. Fry Foundation", "fryfoundation.org", "IL", "private", "/grants"),
    ("The Woods Fund Chicago", "woodsfund.org", "IL", "private", "/grants"),
    ("The MacArthur Foundation Chicago", "macfound.org", "IL", "private", "/grants"),
    ("The Indiana Community Foundation", "indianacf.org", "IN", "community", "/grants"),
    ("The Lilly Endowment", "lillyendowment.org", "IN", "private", "/grants"),
    ("The Nina Mason Pulliam Charitable Trust", "ninapulliamtrust.org", "IN", "private", "/grants"),
    ("The Central Indiana Community Foundation", "cicf.org", "IN", "community", "/grants"),
    ("The Greater Cincinnati Foundation", "greatercincinnati.org", "OH", "community", "/grants"),
    ("The Columbus Foundation", "columbusfoundation.org", "OH", "community", "/grants"),
    ("The Cleveland Foundation", "clevelandfoundation.org", "OH", "community", "/grants"),
    ("The George Gund Foundation", "gundfoundation.org", "OH", "private", "/grants"),
    ("The Nord Family Foundation", "nordff.org", "OH", "private", "/grants"),
    ("The St. Luke's Foundation of Cleveland", "stlukesfoundation.org", "OH", "private", "/grants"),
    ("The HealthPath Foundation of Ohio", "healthpathfoundation.org", "OH", "private", "/grants"),
    ("The Greater Toledo Community Foundation", "toledocf.org", "OH", "community", "/grants"),
    ("The Kresge Foundation Detroit", "kresge.org", "MI", "private", "/grants"),
    ("The Community Foundation for Southeast Michigan", "cfsem.org", "MI", "community", "/grants"),
    ("The Grand Rapids Community Foundation", "grfoundation.org", "MI", "community", "/grants"),
    ("The Ann Arbor Area Community Foundation", "aaacf.org", "MI", "community", "/grants"),
    ("The Fremont Area Community Foundation", "facommunityfoundation.org", "MI", "community", "/grants"),
    ("The Duluth Superior Area Community Foundation", "dsacommunityfoundation.org", "MN", "community", "/grants"),
    ("The Minneapolis Foundation", "minneapolisfoundation.org", "MN", "community", "/grants"),
    ("The Saint Paul & Minnesota Foundation", "spmcf.org", "MN", "community", "/grants"),
    ("The McKnight Foundation Minnesota", "mcknight.org", "MN", "private", "/grants"),
    ("The Otto Bremer Trust", "ottobremer.org", "MN", "private", "/grants"),
    ("The Blandin Foundation", "blandinfoundation.org", "MN", "private", "/grants"),
    ("The Northwest Area Foundation", "nwaf.org", "MN", "private", "/grants"),
    ("The Greater Milwaukee Foundation", "greatermilwaukeefoundation.org", "WI", "community", "/grants"),
    ("The Madison Community Foundation", "madisoncommunityfoundation.org", "WI", "community", "/grants"),
    ("The Community Foundation for the Fox Valley Region", "cffoxvalley.org", "WI", "community", "/grants"),
    ("The Greater Green Bay Community Foundation", "ggbcf.org", "WI", "community", "/grants"),
    ("The La Crosse Community Foundation", "laxfoundation.org", "WI", "community", "/grants"),
    ("The Duluth Community Foundation Wisconsin", "duluthfoundation.org", "WI", "community", "/grants"),
    ("The Oshkosh Area Community Foundation", "oshkoshfoundation.org", "WI", "community", "/grants"),
    ("The Waukesha County Community Foundation", "waukeshacf.org", "WI", "community", "/grants"),
    ("The Racine Community Foundation", "racinecommunityfoundation.org", "WI", "community", "/grants"),
    ("The Sheboygan County Community Foundation", "scfoundation.org", "WI", "community", "/grants"),
    ("The Community Foundation of Southern Wisconsin", "cfsw.org", "WI", "community", "/grants"),
    ("The Wisconsin Humanities Council", "wisconsinhumanities.org", "WI", "public", "/grants"),
    ("The Wisconsin Arts Board", "arts.wisconsin.gov", "WI", "public", "/grants"),
    ("The UW System Grants and Awards", "wisconsin.edu", "WI", "public", "/grants-awards"),
    ("The Iowa West Foundation", "iowawestfoundation.org", "IA", "private", "/grants"),
    ("The Greater Des Moines Community Foundation", "dmcf.org", "IA", "community", "/grants"),
    ("The Community Foundation of Greater Dubuque", "dbqfoundation.org", "IA", "community", "/grants"),
    ("The Sioux Falls Area Community Foundation", "sfacf.org", "SD", "community", "/grants"),
    ("The South Dakota Community Foundation", "sdcommunityfoundation.org", "SD", "community", "/grants"),
    ("The North Dakota Community Foundation", "ndcf.net", "ND", "community", "/grants"),
    ("The Montana Community Foundation", "mtcf.org", "MT", "community", "/grants"),
    ("The Montana Healthcare Foundation", "mthf.org", "MT", "private", "/grants"),
    ("The Wyoming Community Foundation", "wycf.org", "WY", "community", "/grants"),
    ("The Colorado Health Foundation", "coloradohealth.org", "CO", "private", "/grants"),
    ("The Colorado Trust", "coloradotrust.org", "CO", "private", "/grants"),
    ("The Denver Foundation", "denverfoundation.org", "CO", "community", "/grants"),
    ("The Rose Community Foundation", "rcfdenver.org", "CO", "community", "/grants"),
    ("The Boettcher Foundation", "boettcherfoundation.org", "CO", "private", "/grants"),
    ("The Gates Family Foundation", "gatesfamilyfoundation.org", "CO", "private", "/grants"),
    ("The Arizona Community Foundation", "azfoundation.org", "AZ", "community", "/grants"),
    ("The Virginia G. Piper Charitable Trust", "pipertrust.org", "AZ", "private", "/grants"),
    ("The Flinn Foundation", "flinn.org", "AZ", "private", "/grants"),
    ("The Thomas R. Brown Foundations", "brownfoundations.org", "AZ", "private", "/grants"),
    ("The New Mexico Community Foundation", "nmcf.org", "NM", "community", "/grants"),
    ("The Santa Fe Community Foundation", "sfcfinfo.org", "NM", "community", "/grants"),
    ("The Con Alma Health Foundation", "conalma.org", "NM", "private", "/grants"),
    ("The Nevada Community Foundation", "nevadacf.org", "NV", "community", "/grants"),
    ("The Utah Community Foundation", "utahcf.org", "UT", "community", "/grants"),
    ("The George S. and Dolores Dore Eccles Foundation", "ecclesfoundation.org", "UT", "private", "/grants"),
    ("The Idaho Community Foundation", "idahocf.org", "ID", "community", "/grants"),
    ("The Oregon Community Foundation", "oregoncf.org", "OR", "community", "/grants"),
    ("The Meyer Memorial Trust", "mmt.org", "OR", "private", "/grants"),
    ("The Ford Family Foundation", "tfff.org", "OR", "private", "/grants"),
    ("The Collins Foundation", "collinsfoundation.org", "OR", "private", "/grants"),
    ("The Washington Community Foundation", "wacf.org", "WA", "community", "/grants"),
    ("The Seattle Foundation", "seattlefoundation.org", "WA", "community", "/grants"),
    ("The Bill & Melinda Gates Foundation Washington", "gatesfoundation.org", "WA", "private", "/grants"),
    ("The Paul G. Allen Family Foundation", "paulallenfamilyfoundation.org", "WA", "private", "/grants"),
    ("The Inatai Foundation", "inatai.org", "WA", "private", "/grants"),
    ("The Alaska Community Foundation", "alaskacf.org", "AK", "community", "/grants"),
    ("The Rasmuson Foundation", "rasmuson.org", "AK", "private", "/grants"),
    ("The Hawaii Community Foundation", "hawaiicommunityfoundation.org", "HI", "community", "/grants"),
    ("The Atherton Family Foundation", "athertonfamilyfoundation.org", "HI", "private", "/grants"),
    ("The California Wellness Foundation", "calwellness.org", "CA", "private", "/grants"),
    ("The California Health Care Foundation", "chcf.org", "CA", "private", "/grants"),
    ("The Blue Shield of California Foundation", "blueshieldcafoundation.org", "CA", "private", "/grants"),
    ("The San Francisco Foundation", "sff.org", "CA", "community", "/grants"),
    ("The East Bay Community Foundation", "ebcf.org", "CA", "community", "/grants"),
    ("The Silicon Valley Community Foundation", "siliconvalleycf.org", "CA", "community", "/grants"),
    ("The Marin Community Foundation", "marincf.org", "CA", "community", "/grants"),
    ("The Sacramento Region Community Foundation", "sacregcf.org", "CA", "community", "/grants"),
    ("The San Diego Foundation", "sdfoundation.org", "CA", "community", "/grants"),
    ("The Weingart Foundation", "weingartfoundation.org", "CA", "private", "/grants"),
    ("The Ralph M. Parsons Foundation", "rmparsonsfoundation.org", "CA", "private", "/grants"),
    ("The Conrad N. Hilton Foundation", "hiltonfoundation.org", "CA", "private", "/grants"),
    ("The W. M. Keck Foundation", "wmkeck.org", "CA", "private", "/grants"),
    ("The Ahmanson Foundation", "theahmansonfoundation.org", "CA", "private", "/grants"),
    ("The California Community Foundation", "calfund.org", "CA", "community", "/grants"),
    ("The Oregon Health & Science University Foundation", "ohsufoundation.org", "OR", "private", "/"),
    ("The March of Dimes Foundation", "marchofdimes.org", None, "private", "/grants"),
    ("The Robert Wood Johnson Foundation Health", "rwjf.org", None, "private", "/en/grants"),
    ("The Wounded Warrior Project Grants", "woundedwarriorproject.org", None, "private", "/grants"),
    ("The Trust for Public Land Grants", "tpl.org", None, "private", "/grants"),
    ("The Nature Conservancy Grants", "nature.org", None, "private", "/grants"),
    ("The National Fish and Wildlife Foundation", "nfwf.org", None, "public", "/grants"),
    ("The Surfrider Foundation Grants", "surfrider.org", None, "private", "/grants"),
    ("The Captain Planet Foundation", "captainplanetfoundation.org", None, "private", "/grants"),
    ("The Whole Kids Foundation", "wholekidsfoundation.org", None, "corporate", "/grants"),
    ("The Walmart Foundation Local Community Grants", "walmart.org", None, "corporate", "/grants"),
    ("The Bank of America Charitable Foundation", "about.bankofamerica.com", None, "corporate", "/grants"),
    ("The Wells Fargo Foundation", "wellsfargo.com", None, "corporate", "/grants"),
    ("The JPMorgan Chase Foundation", "jpmorganchase.com", None, "corporate", "/grants"),
    ("The Citi Foundation", "citigroup.com", None, "corporate", "/grants"),
    ("The Target Foundation", "corporate.target.com", None, "corporate", "/grants"),
    ("The Home Depot Foundation", "corporate.homedepot.com", None, "corporate", "/grants"),
    ("The Lowe's Foundation", "lowes.com", None, "corporate", "/grants"),
    ("The Coca-Cola Foundation", "coca-colacompany.com", None, "corporate", "/grants"),
    ("The PepsiCo Foundation", "pepsico.com", None, "corporate", "/grants"),
    ("The General Mills Foundation", "generalmills.com", None, "corporate", "/grants"),
    ("The Cargill Foundation", "cargill.com", None, "corporate", "/grants"),
    ("The 3M Foundation", "3m.com", None, "corporate", "/grants"),
    ("The Medtronic Foundation", "medtronic.com", None, "corporate", "/grants"),
    ("The UnitedHealth Group Foundation", "unitedhealthgroup.com", None, "corporate", "/grants"),
    ("The Anthem Foundation", "anthemfoundation.org", None, "corporate", "/grants"),
    ("The Aetna Foundation", "aetnafoundation.org", None, "corporate", "/grants"),
    ("The CVS Health Foundation", "cvshealth.com", None, "corporate", "/grants"),
    ("The AbbVie Foundation", "abbvie.com", None, "corporate", "/grants"),
    ("The Merck Foundation", "merck.com", None, "corporate", "/grants"),
    ("The Pfizer Foundation", "pfizer.com", None, "corporate", "/grants"),
    ("The Amgen Foundation", "amgenfoundation.org", None, "corporate", "/grants"),
    ("The Genentech Foundation", "gene.com", None, "corporate", "/grants"),
]

GRANT_KEYWORDS = [
    "grant", "grants", "funding", "fund", "rfp", "rfa", "request for proposals",
    "request for applications", "call for proposals", "loi", "letter of inquiry",
    "opportunity", "applications open", "apply now", "award", "fellowship",
    "scholarship", "deadline", "cycle",
]


def _entry(
    name: str,
    domain: str,
    state_code: str | None,
    funder_type: str,
    feed_url: str | None,
    path: str,
    mode: str,
) -> dict[str, Any]:
    slug = (
        name.lower()
        .replace("&", "and")
        .replace(".", "")
        .replace("'", "")
        .replace(",", "")
        .replace(" ", "-")
    )
    while "--" in slug:
        slug = slug.replace("--", "-")
    return {
        "id": slug.strip("-"),
        "name": name,
        "domain": domain,
        "type": funder_type,
        "state_code": state_code,
        "website": f"https://www.{domain}{path}",
        "feed_url": feed_url,
        "mode": mode,
        "keywords": GRANT_KEYWORDS,
    }


def build() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()

    for name, domain, feed_url, state_code in VERIFIED_RSS:
        entry = _entry(name, domain, state_code, "private", feed_url, "/", "rss")
        if entry["id"] not in seen:
            seen.add(entry["id"])
            entries.append(entry)

    for name, domain, state_code, funder_type, path in FUNDERS:
        entry = _entry(name, domain, state_code, funder_type, None, path, "scrape")
        if entry["id"] not in seen:
            seen.add(entry["id"])
            entries.append(entry)

    return entries


def main() -> None:
    entries = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    rss = sum(1 for e in entries if e["mode"] == "rss")
    print(f"wrote {len(entries)} funders ({rss} rss, {len(entries) - rss} scrape) -> {OUT}")


if __name__ == "__main__":
    main()