"""Security tests: tenant isolation, privilege escalation, and CSRF.

These are written as attacks. Each test states what a malicious tenant would
try and asserts the system refuses. If one of these fails, it is a real
vulnerability, not a style problem.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from accounts.models import Membership, UserSession
from hunter import db as hunter_db
from hunter.models import Match
from tests.saas_helpers import (
    GOOD_PASSWORD,
    add_member,
    make_grant,
    make_match,
    signup,
)


class TestTenantIsolation:
    """One tenant must never observe or modify another tenant's data."""

    def test_cannot_read_another_tenants_match(self, client):
        alpha = signup(client, nonprofit_name="Alpha", state="WI")
        beta_client = TestClient(client.app)
        beta = signup(beta_client, nonprofit_name="Beta", state="CA")

        grant = make_grant(title="Alpha's grant", source="state_WI", state_code="WI")
        match_id = make_match(nonprofit_id=alpha.nonprofit_id, grant_id=grant["id"])

        # Beta knows (or guesses) Alpha's match id. It must be a 404, not a 403:
        # a 403 would confirm the row exists.
        r = beta.get(f"/api/nonprofits/{alpha.nonprofit_id}/matches/{match_id}")
        assert r.status_code == 404, r.text

    def test_cannot_read_another_tenants_match_even_via_own_path(self, client):
        """The IDOR that matters: right match id, wrong tenant in the path.

        Beta points the URL at *its own* nonprofit id but uses Alpha's match id.
        The handler resolves the match by scope, so the mismatch must fail.
        """
        alpha = signup(client, nonprofit_name="Alpha", state="WI")
        beta_client = TestClient(client.app)
        beta = signup(beta_client, nonprofit_name="Beta", state="CA")

        grant = make_grant(title="Alpha grant", source="state_WI", state_code="WI")
        match_id = make_match(nonprofit_id=alpha.nonprofit_id, grant_id=grant["id"])

        r = beta.get(f"/api/nonprofits/{beta.nonprofit_id}/matches/{match_id}")
        assert r.status_code == 404, r.text

    def test_cannot_review_another_tenants_match(self, client):
        alpha = signup(client, nonprofit_name="Alpha", state="WI")
        beta_client = TestClient(client.app)
        beta = signup(beta_client, nonprofit_name="Beta", state="CA")

        grant = make_grant(title="Alpha grant", source="state_WI", state_code="WI")
        match_id = make_match(nonprofit_id=alpha.nonprofit_id, grant_id=grant["id"])

        r = beta.patch(
            f"/api/nonprofits/{alpha.nonprofit_id}/matches/{match_id}",
            json={"status": "APPROVED"},
        )
        assert r.status_code == 404

        with hunter_db.session_scope() as db:
            assert db.get(Match, match_id).status == "NEEDS_REVIEW"

    def test_cannot_read_another_tenants_soul(self, client):
        alpha = signup(client, nonprofit_name="Alpha", state="WI")
        beta_client = TestClient(client.app)
        beta = signup(beta_client, nonprofit_name="Beta", state="CA")

        soul = "location:\n  state: WI\nnonprofit:\n  name: Alpha Secret\n  mission: Confidential\n"
        alpha.put(f"/api/nonprofits/{alpha.nonprofit_id}/soul", json={"content": soul})

        r = beta.get(f"/api/nonprofits/{alpha.nonprofit_id}/soul")
        assert r.status_code == 404, r.text
        assert "Confidential" not in r.text

    def test_cannot_overwrite_another_tenants_soul(self, client):
        alpha = signup(client, nonprofit_name="Alpha", state="WI")
        beta_client = TestClient(client.app)
        beta = signup(beta_client, nonprofit_name="Beta", state="CA")

        original = "location:\n  state: WI\nnonprofit:\n  name: Alpha\n  mission: Original mission\n"
        alpha.put(f"/api/nonprofits/{alpha.nonprofit_id}/soul", json={"content": original})

        attack = "location:\n  state: WI\nnonprofit:\n  name: Pwned\n  mission: Injected\n"
        r = beta.put(
            f"/api/nonprofits/{alpha.nonprofit_id}/soul", json={"content": attack}
        )
        assert r.status_code == 404

        # The original must be intact.
        body = alpha.get(f"/api/nonprofits/{alpha.nonprofit_id}/soul").json()
        assert body["nonprofit"]["name"] == "Alpha"

    def test_cannot_list_another_tenants_drafts(self, client, tmp_path, monkeypatch):
        monkeypatch.setenv(
            "INNER_COURT_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
        )
        alpha = signup(client, nonprofit_name="Alpha", state="WI")
        beta_client = TestClient(client.app)
        beta = signup(beta_client, nonprofit_name="Beta", state="CA")

        soul = (
            "location:\n  state: WI\n"
            "nonprofit:\n  name: Alpha\n  mission: We serve families.\n"
            "templates:\n  need_statement: 'Need: {{ nonprofit.name }}'\n"
        )
        alpha.put(f"/api/nonprofits/{alpha.nonprofit_id}/soul", json={"content": soul})
        grant = make_grant(title="Alpha grant", source="state_WI", state_code="WI")
        match_id = make_match(nonprofit_id=alpha.nonprofit_id, grant_id=grant["id"])
        created = alpha.post(
            f"/api/nonprofits/{alpha.nonprofit_id}/drafts/generate",
            json={"match_id": match_id},
        )
        assert created.status_code == 200, created.text

        # Beta asks for its own drafts. Alpha's must not appear.
        listed = beta.get(f"/api/nonprofits/{beta.nonprofit_id}/drafts").json()
        assert listed == []

        # And Beta cannot fetch a specific draft by id.
        draft_id = created.json()[0]["id"]
        r = beta.get(f"/api/nonprofits/{beta.nonprofit_id}/drafts/{draft_id}")
        assert r.status_code == 404

    def test_cannot_generate_drafts_from_another_tenants_match(self, client):
        alpha = signup(client, nonprofit_name="Alpha", state="WI")
        beta_client = TestClient(client.app)
        beta = signup(beta_client, nonprofit_name="Beta", state="CA")

        soul = "location:\n  state: CA\nnonprofit:\n  name: Beta\n  mission: We serve.\n"
        beta.put(f"/api/nonprofits/{beta.nonprofit_id}/soul", json={"content": soul})

        grant = make_grant(title="Alpha grant", source="state_WI", state_code="WI")
        alpha_match = make_match(nonprofit_id=alpha.nonprofit_id, grant_id=grant["id"])

        r = beta.post(
            f"/api/nonprofits/{beta.nonprofit_id}/drafts/generate",
            json={"match_id": alpha_match},
        )
        assert r.status_code == 404, r.text

    def test_audit_trail_is_not_cross_tenant(self, client):
        alpha = signup(client, nonprofit_name="Alpha", state="WI")
        beta_client = TestClient(client.app)
        beta = signup(beta_client, nonprofit_name="Beta", state="CA")

        grant = make_grant(title="Alpha grant", source="state_WI", state_code="WI")
        match_id = make_match(nonprofit_id=alpha.nonprofit_id, grant_id=grant["id"])
        alpha.post(f"/api/nonprofits/{alpha.nonprofit_id}/matches/{match_id}/approve")

        events = beta.get(f"/api/nonprofits/{beta.nonprofit_id}/audit").json()
        for event in events:
            assert event.get("actor_email") != alpha.email

    def test_non_member_is_refused_outright(self, client):
        """A signed-in user who is not a member of the target tenant gets 404."""
        alpha = signup(client, nonprofit_name="Alpha", state="WI")
        outsider_client = TestClient(client.app)
        outsider = signup(outsider_client, nonprofit_name="Outsider Inc", state="CA")

        r = outsider.get(f"/api/nonprofits/{alpha.nonprofit_id}/matches")
        assert r.status_code == 404, "membership failure must not confirm the tenant exists"


class TestPrivilegeEscalation:
    """Role boundaries must hold against a determined member."""

    def _owner_and_viewer(self, client):
        owner = signup(client, nonprofit_name="Org", state="WI")
        viewer_email = "viewer@example.org"
        viewer = add_member(owner, viewer_email, role="viewer")
        return owner, viewer

    def test_viewer_cannot_update_soul(self, client):
        owner, viewer = self._owner_and_viewer(client)
        soul = "location:\n  state: WI\nnonprofit:\n  name: Org\n  mission: M\n"
        owner.put(f"/api/nonprofits/{owner.nonprofit_id}/soul", json={"content": soul})

        r = viewer.put(
            f"/api/nonprofits/{owner.nonprofit_id}/soul",
            json={"content": soul.replace("Org", "Hijacked")},
        )
        assert r.status_code == 403

    def test_viewer_cannot_review_matches(self, client):
        """A viewer may read the inbox but not decide on a grant."""
        owner, viewer = self._owner_and_viewer(client)
        grant = make_grant(title="G", source="state_WI", state_code="WI")
        match_id = make_match(nonprofit_id=owner.nonprofit_id, grant_id=grant["id"])

        r = viewer.patch(
            f"/api/nonprofits/{owner.nonprofit_id}/matches/{match_id}",
            json={"status": "APPROVED"},
        )
        assert r.status_code == 403

    def test_viewer_can_read_matches(self, client):
        owner, viewer = self._owner_and_viewer(client)
        grant = make_grant(title="G", source="state_WI", state_code="WI")
        make_match(nonprofit_id=owner.nonprofit_id, grant_id=grant["id"])

        r = viewer.get(f"/api/nonprofits/{owner.nonprofit_id}/matches")
        assert r.status_code == 200

    def test_member_cannot_grant_admins(self, client):
        """Only admins may change roles; a member must not promote themselves."""
        owner = signup(client, nonprofit_name="Org", state="WI")
        member = add_member(owner, "member@example.org", role="member")

        r = member.patch(
            f"/api/nonprofits/{owner.nonprofit_id}/members/{member.user_id}",
            json={"role": "owner"},
        )
        assert r.status_code == 403

        with hunter_db.session_scope() as db:
            row = (
                db.query(Membership)
                .filter_by(nonprofit_id=owner.nonprofit_id, user_id=member.user_id)
                .one()
            )
            assert row.role == "member", "self-promotion must not have taken effect"

    def test_cannot_escalate_via_a_different_tenant(self, client):
        """Changing roles in a tenant you administer must not affect another."""
        owner = signup(client, nonprofit_name="Alpha", state="WI")
        victim_client = TestClient(client.app)
        victim = signup(victim_client, nonprofit_name="Beta", state="CA")

        # Alpha's owner has no standing in Beta. The victim's membership is in
        # Beta; Alpha tries to demote the victim.
        r = owner.patch(
            f"/api/nonprofits/{victim.nonprofit_id}/members/{victim.user_id}",
            json={"role": "viewer"},
        )
        assert r.status_code == 404

    def test_cannot_remove_the_last_owner(self, client):
        owner = signup(client, nonprofit_name="Org", state="WI")
        r = owner.delete(
            f"/api/nonprofits/{owner.nonprofit_id}/members/{owner.user_id}"
        )
        assert r.status_code in (400, 409, 422), (
            "removing the last owner would orphan the organization"
        )

    def test_non_staff_cannot_read_hunter_runs(self, client):
        owner = signup(client, nonprofit_name="Org", state="WI")
        assert owner.get("/api/runs").status_code == 403

    def test_unknown_tenant_id_is_not_a_membership(self, client):
        owner = signup(client, nonprofit_name="Org", state="WI")
        r = owner.get("/api/nonprofits/999999/matches")
        assert r.status_code == 404


class TestCsrf:
    """Cookie sessions are ambient, so writes need a double-submit token."""

    def _signed_in_without_csrf(self, client):
        """Sign up, then drop the CSRF cookie but keep the session cookie."""
        account = signup(client, nonprofit_name="Org", state="WI")
        client.cookies.delete("ga_csrf")
        return account

    def test_write_without_csrf_header_is_rejected(self, client):
        owner = signup(client, nonprofit_name="Org", state="WI")
        soul = "location:\n  state: WI\nnonprofit:\n  name: Org\n  mission: M\n"
        owner.put(f"/api/nonprofits/{owner.nonprofit_id}/soul", json={"content": soul})

        grant = make_grant(title="G", source="state_WI", state_code="WI")
        match_id = make_match(nonprofit_id=owner.nonprofit_id, grant_id=grant["id"])
        client.cookies.delete("ga_csrf")

        r = client.patch(
            f"/api/nonprofits/{owner.nonprofit_id}/matches/{match_id}",
            json={"status": "APPROVED"},
        )
        assert r.status_code == 403, r.text

    def test_write_with_wrong_csrf_token_is_rejected(self, client):
        owner = signup(client, nonprofit_name="Org", state="WI")
        r = client.patch(
            f"/api/nonprofits/{owner.nonprofit_id}/matches/1",
            json={"status": "APPROVED"},
            headers={"X-CSRF-Token": "not-the-real-token"},
        )
        assert r.status_code == 403

    def test_read_does_not_need_csrf(self, client):
        owner = signup(client, nonprofit_name="Org", state="WI")
        assert owner.get("/api/grants").status_code == 200

    def test_bearer_token_write_is_exempt_from_csrf(self, client):
        """A bearer token is not ambient, so CSRF does not apply to it."""
        owner = signup(client, nonprofit_name="Org", state="WI")
        created = owner.post("/api/auth/tokens", json={"name": "ci"})
        assert created.status_code == 201, created.text
        raw = created.json()["token"]

        fresh = TestClient(client.app)
        r = fresh.post(
            "/api/auth/tokens",
            json={"name": "made-with-bearer"},
            headers={"Authorization": f"Bearer {raw}"},
        )
        assert r.status_code == 201, r.text


class TestAuthentication:
    def test_wrong_password_is_rejected(self, client):
        owner = signup(client, nonprofit_name="Org", state="WI")
        r = client.post(
            "/api/auth/login",
            json={"email": owner.email, "password": "wrong-password-entirely"},
        )
        assert r.status_code == 401

    def test_login_does_not_disclose_whether_email_exists(self, client):
        owner = signup(client, nonprofit_name="Org", state="WI")
        known = client.post(
            "/api/auth/login",
            json={"email": owner.email, "password": "wrong-password-entirely"},
        )
        unknown = client.post(
            "/api/auth/login",
            json={"email": "nobody@example.org", "password": "wrong-password-entirely"},
        )
        assert known.status_code == unknown.status_code == 401
        assert known.json()["detail"] == unknown.json()["detail"]

    def test_password_is_hashed_not_stored(self, client):
        owner = signup(client, nonprofit_name="Org", state="WI")
        from accounts.models import User

        with hunter_db.session_scope() as db:
            row = db.query(User).filter_by(email=owner.email).one()
            assert row.password_hash != GOOD_PASSWORD
            assert GOOD_PASSWORD not in row.password_hash

    def test_session_cookie_is_httponly(self, client):
        response = client.post(
            "/api/auth/signup",
            json={
                "email": "cookie@example.org",
                "password": GOOD_PASSWORD,
                "nonprofit_name": "Org",
                "state": "WI",
            },
        )
        header = response.headers.get("set-cookie", "")
        assert "ga_session=" in header
        assert "HttpOnly" in header

    def test_deleted_session_token_stops_working(self, client):
        owner = signup(client, nonprofit_name="Org", state="WI")
        assert owner.get("/api/auth/me").status_code == 200

        with hunter_db.session_scope() as db:
            sessions = (
                db.query(UserSession)
                .filter_by(user_id=owner.user_id)
                .all()
            )
            for s in sessions:
                db.delete(s)

        assert client.get("/api/auth/me").status_code == 401

    def test_weak_passwords_are_refused(self, client):
        weak = client.post(
            "/api/auth/signup",
            json={
                "email": "weak@example.org",
                "password": "short",
                "nonprofit_name": "Org",
                "state": "WI",
            },
        )
        assert weak.status_code == 422

    def test_duplicate_signup_is_refused(self, client):
        owner = signup(client, nonprofit_name="Org", state="WI")
        again = TestClient(client.app)
        r = again.post(
            "/api/auth/signup",
            json={
                "email": owner.email,
                "password": GOOD_PASSWORD,
                "nonprofit_name": "Copycat",
                "state": "WI",
            },
        )
        assert r.status_code in (400, 409)


class TestInjectionAndInputHandling:
    def test_grant_title_is_returned_verbatim_never_rendered_as_html(self, client):
        """Grant text comes from third-party feeds, so it is stored as data.

        The API returns JSON and the frontend inserts it with textContent; this
        asserts the payload survives intact rather than being mangled, and that
        no HTML content-type is emitted for it.
        """
        owner = signup(client, nonprofit_name="Org", state="WI")
        payload = "<script>alert('xss')</script>"
        grant = make_grant(title=payload, source="state_WI", state_code="WI")

        r = owner.get(f"/api/grants/{grant['id']}")
        assert r.status_code == 200
        assert r.json()["title"] == payload
        assert r.headers["content-type"].startswith("application/json")

    def test_sql_metacharacters_in_search_are_parameterised(self, client):
        owner = signup(client, nonprofit_name="Org", state="WI")
        make_grant(title="Legit Grant", source="state_WI", state_code="WI")

        for probe in ["'; DROP TABLE grants; --", "%' OR '1'='1", "_%"]:
            r = owner.get("/api/grants", params={"q": probe})
            assert r.status_code == 200, r.text
        # The table must still exist.
        assert owner.get("/api/grants").json()["total"] == 1

    def test_oversized_soul_is_refused_by_validation(self, client):
        owner = signup(client, nonprofit_name="Org", state="WI")
        r = owner.put(
            f"/api/nonprofits/{owner.nonprofit_id}/soul",
            json={"content": "x" * 300_000},
        )
        assert r.status_code == 422

    def test_malformed_json_is_refused(self, client):
        owner = signup(client, nonprofit_name="Org", state="WI")
        r = owner.post(
            "/api/soul/validate",
            content=b"{not json",
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 422


class TestSecurityHeaders:
    def test_api_responses_are_locked_down(self, client):
        response = client.get("/api/health")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        csp = response.headers.get("Content-Security-Policy", "")
        assert "frame-ancestors 'none'" in csp

    def test_unknown_host_header_is_rejected(self, client):
        r = client.get("/api/health", headers={"Host": "evil.example.com"})
        assert r.status_code == 400


class TestRateLimiting:
    """Limits protect the credential endpoints specifically."""

    def test_login_attempts_are_limited(self, client, monkeypatch):
        monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
        from hunter.config import reload_settings

        reload_settings()

        from api import ratelimit

        ratelimit.reset_all()

        owner = signup(client, nonprofit_name="Org", state="WI")
        statuses = []
        for _ in range(25):
            r = client.post(
                "/api/auth/login",
                json={"email": owner.email, "password": "definitely-wrong-pass"},
            )
            statuses.append(r.status_code)

        assert 429 in statuses, "repeated failed logins must eventually be throttled"

    def test_waitlist_is_rate_limited(self, client, monkeypatch):
        monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
        from hunter.config import reload_settings

        reload_settings()

        from api import ratelimit

        ratelimit.reset_all()

        statuses = []
        for i in range(30):
            r = client.post(
                "/api/waitlist",
                json={"email": f"lead{i}@example.org"},
            )
            statuses.append(r.status_code)
        assert 429 in statuses


class TestWaitlist:
    def test_valid_email_is_accepted(self, client):
        r = client.post("/api/waitlist", json={"email": "lead@example.org"})
        assert r.status_code == 202

    def test_duplicate_email_is_not_disclosed(self, client):
        first = client.post("/api/waitlist", json={"email": "dupe@example.org"})
        second = client.post("/api/waitlist", json={"email": "dupe@example.org"})
        assert first.status_code == second.status_code == 202
        assert first.json() == second.json()

    def test_invalid_email_is_refused(self, client):
        r = client.post("/api/waitlist", json={"email": "not-an-email"})
        assert r.status_code == 422

    def test_waitlist_creates_no_user(self, client):
        client.post("/api/waitlist", json={"email": "lead@example.org"})
        from accounts.models import User

        with hunter_db.session_scope() as db:
            assert db.query(User).filter_by(email="lead@example.org").one_or_none() is None