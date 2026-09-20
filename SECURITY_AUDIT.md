# Security Review — Granted Agent platform

Scope: the multi-tenant SaaS layer (`accounts/`, `api/`, `billing/`,
`tracking/`, `inner_court/vault.py`, `frontend/`) — authentication,
authorisation, tenancy isolation, the Stripe integration and the soul vault.
The hunter ingestion path was reviewed only where it touches tenant data.

Method: a read of every authentication and authorisation path, plus an
executable attack suite in `tests/test_security.py`. Each test asserts what a
hostile tenant would attempt and that the system refuses. A failing test is a
vulnerability, not a style problem. Findings below are ordered by severity, with
the fixes that landed and the tests that hold them fixed.

## Summary

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| 1 | High | A viewer could approve or reject grants | Fixed |
| 2 | High | Two sessions per request deadlocked the database | Fixed |
| 3 | Medium | Login throttling failed on SQLite | Fixed |
| 4 | Medium | Security-critical configuration was undocumented | Fixed |
| 5 | Low | Caller-supplied billing redirect URLs | Accepted |

Verified sound, with tests: tenant isolation on matches, souls, drafts and
audit trails; cross-tenant IDOR; role-change escalation; CSRF on cookie
sessions; login user-enumeration through body and timing; SQL injection through
the grant search; SSRF and path traversal on static assets.

---

## 1. High — A viewer could approve or reject grants

**Where:** `api/grants.py`, `review_match`.

**What was wrong.** `PATCH /api/nonprofits/{id}/matches/{match_id}` accepted any
member of the organization. The role model intends `viewer` to be read-only —
the role exists so a board member or an accountant can be given sight of the
inbox without the ability to act on it. A viewer could therefore set any match
to `APPROVED` or `REJECTED`, writing a decision into the audit trail attributed
to them, and removing the grant from review.

The write was not merely cosmetic: it moves a grant out of `NEEDS_REVIEW`,
which is what the human-in-the-loop queue reads, so the organization could
silently lose a funding opportunity it had not decided on.

**Fix.** `review_match` now requires the `member` role, matching the guard that
already protected soul writes in `inner_court.py`.

**Held by:** `TestPrivilegeEscalation::test_viewer_cannot_review_matches`,
and `test_viewer_can_read_matches` to confirm the fix did not overcorrect into
blocking reads.

## 2. High — Two database sessions per request

**Where:** `api/deps.py`, `api/main.py`, `hunter/db.py`.

**What was wrong.** The routers depended on `api.main.get_db`, while the
authentication layer used a second generator, `api.deps._get_db_session`, that
wrapped it. FastAPI caches a dependency by the identity of the callable, so
these were two distinct dependencies and every authenticated request opened
**two** SQLAlchemy sessions — two live transactions against the same database.

Against PostgreSQL that is wasteful. Against SQLite it is fatal: writes take a
database-wide lock, so the auth layer's session (which flushes on login and
token use) held the write lock while the route body tried to insert the usage
event for the same request. The insert blocked until the driver's 5-second
timeout expired, then failed with `database is locked`. Roughly half the API
test suite failed this way, and the run took 10 minutes of accumulated
timeouts instead of 20 seconds.

This was found by reproduction rather than inspection: a minimal script that
signed up and listed grants failed deterministically on the second request.

**Fix.** `get_db` in `hunter/db.py` is now the single session dependency for the
whole application. Every router imports it from there, and `_get_db_session` is
an alias of the same callable — not a wrapper — so FastAPI's cache collapses
them into one session, one transaction, one commit. As defence in depth, the
SQLite engine also gets a 30-second busy timeout instead of the 5-second
default.

**Held by:** `tests/test_api.py` in full — the suite went from 21 failures to
40 passes in 20 seconds. `tests/conftest.py` asserts the engine is SQLite before
running, so these tests can never point at a live database.

## 3. Medium — Login throttling failed on SQLite

**Where:** `accounts/models.py`, `LoginAttempt`.

**What was wrong.** The primary key was declared `BigInteger`. SQLite only
treats a column declared exactly `INTEGER PRIMARY KEY` as an alias for the
rowid, so a `BIGINT` primary key gets no automatic value and every insert failed
with `NOT NULL constraint failed: login_attempts.id`. On a SQLite deployment
every login attempt raised, which means the record that rate limiting and
abuse review depend on was never written.

The same defect was already known for `usage_events` and fixed there; the
`login_attempts` table was missed.

**Fix.** A `BigPK` type — `BigInteger` with a SQLite variant of `Integer` —
keeps `BIGINT` where it matters (PostgreSQL, where the table grows with traffic
and will outgrow 32 bits) and works on SQLite.

**Held by:** `TestAuthentication::test_wrong_password_is_rejected` and the rate
limiting tests, which now reach the limiter instead of erroring first.

## 4. Medium — Security-critical configuration was undocumented

**Where:** `.env.example`.

**What was wrong.** Twenty-eight settings had no entry in `.env.example`,
including two that decide whether protections are on at all:

* `RATE_LIMIT_ENABLED` — defaults to true, but an operator reading the example
  file could not know it exists, and disabling it silently removes throttling
  from login and the mail-sending endpoints.
* `ALLOWED_HOSTS` — the Host-header allow-list. Its empty default is safe
  because the list is derived from the configured base URLs, but an operator
  who does not know the setting exists cannot add a second hostname, and will
  instead be tempted to disable the check.

Also undocumented: `STRIPE_WEBHOOK_SECRET` (without which billing refuses to
run), `SESSION_COOKIE_SECURE`, `ENVIRONMENT`, and the SMTP block.

**Fix.** `.env.example` now documents every setting, grouped by purpose, with
the security-relevant defaults and the consequence of changing them stated. A
scripted check confirmed no setting remains undocumented.

## 5. Low — Caller-supplied billing redirect URLs

**Where:** `api/billing.py`, `CheckoutIn.success_url` / `cancel_url`,
`PortalIn.return_url`.

**What was wrong.** The owner may pass absolute URLs that are forwarded to
Stripe as the post-checkout destination. Stripe validates and hosts these
redirects, and only a tenant owner can set them, so the exposure is narrow:
a phishing link that makes a checkout return to an attacker-controlled page.
It is not an open redirect on our own domain, because we never redirect to the
value ourselves.

**Status:** accepted, not fixed. The legitimate use — a customer on their own
domain wanting to be returned to it — is real, and restricting the value to
known origins would break it. If this becomes a hosted offering with fixed
domains, the URLs should be derived from configuration instead of accepted from
the request; noted here so that decision is deliberate rather than forgotten.

---

## Verified sound

Each item below was attacked and held. The named test is where the refusal is
asserted.

* **Tenant isolation.** A tenant cannot read or review another tenant's
  matches, read or overwrite another tenant's soul, list or fetch another
  tenant's drafts, or generate drafts from another tenant's match. The
  deliberate IDOR case — the correct match id under the attacker's *own*
  tenant path — is refused, because the match is resolved by scope rather than
  by id alone. `TestTenantIsolation`, 9 tests.
* **Non-disclosure of tenant existence.** A non-member gets 404, not 403, and
  no response body distinguishes "not a member" from "no such tenant".
* **Role escalation.** A member cannot change roles; a viewer cannot write the
  soul or review matches; an admin cannot grant `owner` or act on a peer; a
  tenant admin has no standing in another tenant; the last owner cannot be
  removed. `TestPrivilegeEscalation`, 8 tests.
* **CSRF.** Cookie-authenticated writes without a matching double-submit token
  are refused; reads are unaffected; bearer-token writes are correctly exempt.
  `TestCsrf`, 4 tests.
* **Account enumeration.** Login returns identical status, body and cost for a
  wrong password and an unknown address; signup and password reset answer 202
  either way; signup on an existing address is refused at 409 only after a
  valid password is supplied. `TestAuthentication` and `TestWaitlist`.
* **Credential storage.** Passwords are argon2id and never appear in the stored
  column; session cookies are `HttpOnly`; deleting a session row invalidates
  the token immediately. `TestAuthentication`.
* **Injection.** Grant titles from third-party feeds round-trip intact as JSON
  and are never served as HTML; SQL metacharacters in the search parameter are
  parameterised and the table survives; oversized payloads and malformed JSON
  are refused by validation. `TestInjectionAndInputHandling`, 4 tests.
* **Rate limiting.** Repeated failed logins and repeated waitlist submissions
  eventually return 429. `TestRateLimiting`.
* **Stripe webhooks.** The signature is verified over the raw body before the
  payload is parsed, and each event id is recorded so a replayed delivery is a
  no-op — a replayed event cannot grant a second subscription period.
* **Vault cryptography.** AES-256-GCM with a per-tenant data key wrapped under
  the master key; a wrong key or a modified ciphertext fails authentication
  rather than decrypting to garbage; only secret-free projections reach
  `soul_json`, and the API exposes configured secret *keys*, never values.
* **Static assets.** Asset paths are resolved and checked against the static
  directory, so traversal cannot escape it; the names are constant, not
  caller-supplied.
* **Security headers.** `nosniff`, `DENY` framing and a closed CSP on API
  responses; an unknown Host header is rejected before any handler runs.

## Residual risk and recommendations

1. **No TLS enforcement in the application.** `Secure` is set on cookies
   automatically when `PUBLIC_BASE_URL` is https, which assumes the operator
   configures it correctly. Terminating TLS at a proxy is correct; forwarding
   plaintext is not. A production checklist should require `PUBLIC_BASE_URL`
   and `ENVIRONMENT=production`.
2. **Rate limiting is in-process.** The token buckets are module-level and
   per-worker, so limits scale with worker count and reset on restart. Behind
   more than one worker this should move to a shared store.
3. **The breached-password check is a 28-entry deny-list.** It is a floor, not
   the control; length and argon2 cost carry the weight. Add a k-anonymity range
   query against a breach corpus when the signup path can afford a network call.
4. **No second factor.** Worth adding for `owner` accounts before the platform
   holds customer payment relationships.
5. **HTML pages carry no CSP.** Only `/api/*` responses do. `app.html` renders
   third-party grant text; it inserts via `textContent`, but a page-level CSP
   would make that guarantee enforced rather than conventional.