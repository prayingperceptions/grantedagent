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

## Platform (SaaS)

Beyond the hunter, the repository carries the multi-tenant product: accounts,
organizations, billing, the review inbox and the vault.

### Tenancy model

Every tenant-owned row hangs off a `nonprofit_id`. A route never receives a
bare id: it receives a `TenantScope`, which can only be constructed by resolving
a real `Membership` row for the caller. A handler that forgets to check tenancy
cannot be written, because there is no unscoped id in scope to forget about.

Two rules make the boundary auditable:

* Tenant context comes from the **URL path**, never from a header or body
  field, so the authorisation decision is visible in access logs.
* A missing membership answers **404, not 403**. A 403 for an existing tenant
  and a 404 for a missing one would let an attacker enumerate customer ids.

Roles are `viewer < member < admin < owner`. Reads need membership; writing
souls and drafts and reviewing matches needs `member`; member management and
soul deletion need `admin`; billing needs `owner`. A caller may only act on a
strictly lower role and may not grant a role at or above their own, so an admin
cannot mint an owner and two admins cannot demote each other.

### Authentication

* Passwords are hashed with **argon2id** (19 MiB, 2 iterations).
* Session and API tokens are 256 bits of CSPRNG output, stored only as a
  SHA-256 digest; a database dump yields no live sessions.
* Browser sessions ride in an `HttpOnly`, `SameSite=Lax` cookie. Because that
  cookie is ambient, every state-changing request also needs a double-submit
  CSRF token. Bearer tokens are exempt: the browser does not attach them
  automatically.
* Login answers identically - same status, same body, same CPU cost - for a
  wrong password, an unknown address and a disabled account, so it cannot be
  used to probe for accounts.
* Login, signup and mail-sending endpoints are rate limited per IP and, for
  login, per account.

### Soul vault

Each organization's soul is encrypted with AES-256-GCM under a per-tenant data
key, which is wrapped by the `INNER_COURT_KEY` master key (envelope
encryption). A database dump yields neither a key nor a mission statement.
Only a sanitised, secret-free projection is mirrored into `soul_json` for
templating and search.

### Billing

Stripe webhooks verify the signature against the raw request body before the
payload is trusted, and each event id is recorded so a replayed delivery is a
no-op. Billing self-disables unless both `STRIPE_SECRET_KEY` and
`STRIPE_WEBHOOK_SECRET` are set.

### Security tests

```bash
pytest tests/test_security.py    # tenant isolation, privilege escalation, CSRF
```

These are written as attacks: each one states what a malicious tenant would try
and asserts the system refuses. A failure is a vulnerability, not a style
problem. See `SECURITY_AUDIT.md` for the review that produced them and the
findings it surfaced.
