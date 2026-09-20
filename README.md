# Granted Agent

Granted Agent is an open-source Grant Intelligence OS that learns your nonprofit and hunts grants 24/7.

Open-source Hunter that learns your nonprofit via private Inner Court (soul.md) and hunts grants 24/7. Scribe drafts LOIs. Human approves.

## Hunter

The Hunter is Granted Agent's 24/7 opportunity discovery engine. It sweeps
federal, national foundation, and state/local funding sources on a 6 hour
cadence and lands everything in one deduplicated `grants` table.

### Sources

| Module | Scope | Auth |
| --- | --- | --- |
| `hunter/sources/grants_gov.py` | All federal opportunities via `search2` + `fetchOpportunity` detail backfill | none |
| `hunter/sources/simpler_grants.py` | Simpler Grants (HHS) federal index | `SIMPLER_GRANTS_API_KEY` |
| `hunter/sources/sam_gov.py` | SAM.gov contract opportunities | `SAM_GOV_API_KEY` |
| `hunter/sources/us_foundations.py` | 250+ US funders (RSS first, Playwright fallback) | none |
| `hunter/sources/state_local_scraper.py` | All 50 states + DC | none |

Key-gated sources self-disable with a `skipped` reason rather than failing the
run, so an unconfigured deployment still completes.

### Data model

`grants` holds the landing zone for every source:

```
id, external_id, title, agency, deadline, amount_min, amount_max,
description, url, raw_json, source, state_code, dedupe_hash
```

`source` is one of `federal`, `national_foundation`, or `state_<CODE>`.
`state_code` is null for federal and national foundation records.
`dedupe_hash` is a unique sha256 of `title + agency + deadline` after
normalization (`hunter/deduper.py`), so the same opportunity reported by
several sources is stored once.

### Running

```bash
uv venv .venv && . .venv/bin/activate
uv pip install -r requirements.txt
playwright install chromium

cp .env.example .env          # set DATABASE_URL, STATES_FILTER, API keys

python -m hunter.scheduler --once       # one hunt, prints a JSON summary
python -m hunter.scheduler              # blocking 6 hour loop
python -m hunter.scheduler --states WI  # override STATES_FILTER
python -m hunter.scheduler --no-persist # dry run without a database
```

`STATES_FILTER` accepts `ALL`, a single code (`WI`), or a list (`WI,MN,CA`).

A hunt logs and records:

```
federal_found, foundation_found, state_total, state_breakdown,
inserted, updated, total_unique
```

### Regenerating data

```bash
python scripts/build_foundations_registry.py   # hunter/data/foundations_registry.json
python scripts/build_state_configs.py          # hunter/states/*.json
```

The state configs use a two-pass extractor: structured JSON-LD / `__NEXT_DATA__`
first, then a keyword-filtered anchor scan scoped to the portal's own domain.

### Tests

```bash
pytest                      # everything, including live API acceptance tests
pytest --no-network         # unit tests only
pytest -m network           # acceptance criteria only
```

Acceptance: `STATES_FILTER=ALL` yields 20+ federal and 5+ foundation
opportunities; `STATES_FILTER=WI` yields Wisconsin-scoped opportunities.
