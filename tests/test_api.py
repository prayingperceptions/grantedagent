"""End-to-end API tests.

These exercise the whole chain against a real (temporary, file-backed) database:
ingest a grant, score it for a nonprofit, generate a draft, then take it through
human review. No mocks: the scorer uses the real model when available, and the
scoring tests are skipped otherwise.
"""

from __future__ import annotations

import os
from datetime import date, timedelta
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from hunter import db as hunter_db
from hunter.models import (
    STATUS_APPROVED,
    STATUS_NEEDS_REVIEW,
    STATUS_REJECTED,
    Grant,
    Match,
    NonprofitModel,
)
from inner_court.loader import parse_soul

SOUL = """
location:
  city: "Milwaukee"
  state: "WI"
  zip: "53202"
matching_rules:
  states: ["WI", "national"]
  exclusions: ["for-profit"]
nonprofit:
  name: "Milwaukee Families Coalition"
  ein: "39-1234567"
  mission: "We improve health and economic outcomes for families in Milwaukee through direct services and community partnership."
  signatory_name: "Dana Director"
  signatory_title: "Executive Director"
  populations_served: ["low-income families", "youth"]
  focus_areas: ["community health", "food security"]
templates:
  need_statement: "Need text."
  budget_narrative: "Budget text."
  organizational_history: "History text."
  alignment_statement: "Alignment text."
"""

WI_GRANT = (
    "Wisconsin Community Health Grant: funding for Wisconsin nonprofits expanding "
    "primary care access for low-income families and youth."
)


@pytest.fixture()
def soul_file(tmp_path, monkeypatch) -> Path:
    path = tmp_path / "soul.md"
    path.write_text(SOUL)
    monkeypatch.setenv("INNER_COURT_PATH", str(path))
    return path


@pytest.fixture()
def seeded(client, owner):
    """One grant and a scored match belonging to the signed-in tenant."""
    from tests.saas_helpers import make_grant, make_match

    grant = make_grant(
        title=WI_GRANT,
        source="state_WI",
        state_code="WI",
        agency="Wisconsin Health Fund",
    )
    match_id = make_match(
        nonprofit_id=owner.nonprofit_id, grant_id=grant["id"], score=91.5
    )
    return {
        "nonprofit_id": owner.nonprofit_id,
        "grant_id": grant["id"],
        "match_id": match_id,
    }


class TestHealth:
    def test_health_ok(self, client):
        body = client.get("/api/health").json()
        assert body["status"] == "ok"
        assert body["database"] is True


class TestAuthGate:
    """The catalogue is the product, so it is not public."""

    def test_grants_requires_auth(self, client):
        assert client.get("/api/grants").status_code == 401

    def test_matches_requires_auth(self, client, owner):
        anonymous = TestClient(client.app)
        r = anonymous.get(f"/api/nonprofits/{owner.nonprofit_id}/matches")
        assert r.status_code == 401

    def test_me_requires_auth(self, client):
        assert client.get("/api/auth/me").status_code == 401

    def test_health_is_public(self, client):
        assert client.get("/api/health").status_code == 200


class TestGrants:
    def test_lists_grants(self, client, owner, seeded):
        body = owner.get("/api/grants").json()
        assert body["total"] == 1
        assert body["items"][0]["source"] == "state_WI"

    def test_filter_by_state(self, owner, seeded):
        assert owner.get("/api/grants?state_code=WI").json()["total"] == 1
        assert owner.get("/api/grants?state_code=CA").json()["total"] == 0

    def test_filter_by_source(self, owner, seeded):
        assert owner.get("/api/grants?source=state_WI").json()["total"] == 1
        assert owner.get("/api/grants?source=federal").json()["total"] == 0

    def test_title_search(self, owner, seeded):
        assert owner.get("/api/grants?q=Community").json()["total"] == 1
        assert owner.get("/api/grants?q=zzz").json()["total"] == 0

    def test_deadline_filter(self, owner, seeded):
        soon = date.today() + timedelta(days=60)
        assert owner.get(f"/api/grants?deadline_before={soon}").json()["total"] == 1
        past = date.today() - timedelta(days=1)
        assert owner.get(f"/api/grants?deadline_before={past}").json()["total"] == 0

    def test_get_one(self, owner, seeded):
        r = owner.get(f"/api/grants/{seeded['grant_id']}")
        assert r.status_code == 200
        assert r.json()["title"] == WI_GRANT

    def test_missing_grant_404(self, owner, seeded):
        assert owner.get("/api/grants/999999").status_code == 404

    def test_pagination_bounds(self, owner, seeded):
        assert owner.get("/api/grants?limit=0").status_code == 422
        assert owner.get("/api/grants?limit=500").status_code == 422


class TestMatches:
    def test_lists_for_nonprofit(self, owner, seeded):
        body = owner.get(f"/api/nonprofits/{seeded['nonprofit_id']}/matches").json()
        assert body["total"] == 1
        assert body["items"][0]["score"] == 91.5
        assert body["items"][0]["grant"]["state_code"] == "WI"

    def test_min_score_filter(self, owner, seeded):
        np_id = seeded["nonprofit_id"]
        base = f"/api/nonprofits/{np_id}/matches"
        assert owner.get(f"{base}?min_score=95").json()["total"] == 0
        assert owner.get(f"{base}?min_score=50").json()["total"] == 1

    def test_status_filter(self, owner, seeded):
        np_id = seeded["nonprofit_id"]
        base = f"/api/nonprofits/{np_id}/matches"
        assert owner.get(f"{base}?status=NEEDS_REVIEW").json()["total"] == 1
        assert owner.get(f"{base}?status=APPROVED").json()["total"] == 0

    def test_invalid_status_422(self, owner, seeded):
        r = owner.get(f"/api/nonprofits/{seeded['nonprofit_id']}/matches?status=BOGUS")
        assert r.status_code == 422

    def test_ordered_by_score_desc(self, owner, seeded):
        items = owner.get(
            f"/api/nonprofits/{seeded['nonprofit_id']}/matches"
        ).json()["items"]
        scores = [i["score"] for i in items]
        assert scores == sorted(scores, reverse=True)

    def test_approve_records_review(self, owner, seeded):
        r = owner.patch(
            f"/api/nonprofits/{seeded['nonprofit_id']}/matches/{seeded['match_id']}",
            json={"status": STATUS_APPROVED, "note": "Looks good"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["status"] == STATUS_APPROVED

    def test_reviewer_is_the_authenticated_user_not_the_client(self, owner, seeded):
        """A caller must not be able to attribute a decision to someone else."""
        r = owner.patch(
            f"/api/nonprofits/{seeded['nonprofit_id']}/matches/{seeded['match_id']}",
            json={"status": STATUS_APPROVED, "note": "ok", "reviewed_by": "someone-else"},
        )
        assert r.status_code == 200

        with hunter_db.session_scope() as db:
            match = db.get(Match, seeded["match_id"])
            assert match.reviewed_by == owner.email

    def test_reject_via_endpoint(self, owner, seeded):
        r = owner.post(
            f"/api/nonprofits/{seeded['nonprofit_id']}/matches/{seeded['match_id']}/reject"
        )
        assert r.status_code == 200
        assert r.json()["status"] == STATUS_REJECTED

    def test_approve_via_endpoint(self, owner, seeded):
        r = owner.post(
            f"/api/nonprofits/{seeded['nonprofit_id']}/matches/{seeded['match_id']}/approve"
        )
        assert r.status_code == 200
        assert r.json()["status"] == STATUS_APPROVED

    def test_invalid_status_rejected(self, owner, seeded):
        r = owner.patch(
            f"/api/nonprofits/{seeded['nonprofit_id']}/matches/{seeded['match_id']}",
            json={"status": "MAYBE"},
        )
        assert r.status_code == 422

    def test_missing_match_404(self, owner, seeded):
        r = owner.get(
            f"/api/nonprofits/{seeded['nonprofit_id']}/matches/999999"
        )
        assert r.status_code == 404


class TestStatsAndRuns:
    def test_stats_shape(self, owner, seeded):
        body = owner.get(f"/api/nonprofits/{seeded['nonprofit_id']}/stats").json()
        assert body["grants_total"] == 1
        assert body["by_source"]["state_WI"] == 1
        assert body["matches_by_status"]["NEEDS_REVIEW"] == 1

    def test_stats_hides_other_tenants_matches(self, owner, seeded, client):
        """A second tenant's match must not appear in this tenant's breakdown."""
        from tests.saas_helpers import make_grant, make_match, signup

        other_client = TestClient(client.app)
        other = signup(other_client, nonprofit_name="Other Org", state="CA")
        grant = make_grant(title="CA Grant", source="state_CA", state_code="CA")
        make_match(nonprofit_id=other.nonprofit_id, grant_id=grant["id"], score=99.0)

        body = owner.get(f"/api/nonprofits/{seeded['nonprofit_id']}/stats").json()
        assert body["matches_by_status"]["NEEDS_REVIEW"] == 1, (
            "the other tenant's match must not be counted"
        )

    def test_runs_requires_staff(self, owner):
        assert owner.get("/api/runs").status_code == 403


class TestSoulEndpoints:
    def test_put_then_get_soul(self, owner):
        r = owner.put(f"/api/nonprofits/{owner.nonprofit_id}/soul", json={"content": SOUL})
        assert r.status_code == 200, r.text
        body = owner.get(f"/api/nonprofits/{owner.nonprofit_id}/soul").json()
        assert body["location"]["state"] == "WI"
        assert body["nonprofit"]["name"] == "Milwaukee Families Coalition"

    def test_soul_never_returns_secrets(self, owner):
        content = SOUL + "\nsecrets:\n  api_key: 'sk-live-DO-NOT-LEAK'\n"
        owner.put(f"/api/nonprofits/{owner.nonprofit_id}/soul", json={"content": content})
        raw = owner.get(f"/api/nonprofits/{owner.nonprofit_id}/soul").text
        assert "sk-live-DO-NOT-LEAK" not in raw
        body = owner.get(f"/api/nonprofits/{owner.nonprofit_id}/soul").json()
        assert body["secrets_configured"] == ["api_key"]

    def test_soul_stored_encrypted(self, owner):
        """The plaintext mission must not be readable from the raw column."""
        owner.put(f"/api/nonprofits/{owner.nonprofit_id}/soul", json={"content": SOUL})
        with hunter_db.session_scope() as db:
            row = db.get(NonprofitModel, owner.nonprofit_id)
            assert row.soul_encrypted
            assert "improve health and economic outcomes" not in row.soul_encrypted
            assert row.soul_encrypted.startswith("v1.")

    def test_soul_missing_404(self, owner):
        assert owner.get(f"/api/nonprofits/{owner.nonprofit_id}/soul").status_code == 404

    def test_validate_accepts_good_soul(self, owner):
        body = owner.post("/api/soul/validate", json={"content": SOUL}).json()
        assert body["valid"] is True
        assert body["errors"] == []

    def test_validate_rejects_bad_state(self, owner):
        bad = SOUL.replace('state: "WI"', 'state: "Wisconsin"')
        body = owner.post("/api/soul/validate", json={"content": bad}).json()
        assert body["valid"] is False
        assert body["errors"]

    def test_validate_warns_on_explicitly_blank_templates(self, owner):
        content = (
            "location:\n  state: WI\n"
            "templates:\n  need_statement: '  '\n"
            "nonprofit:\n  name: X\n  mission: M\n"
        )
        body = owner.post("/api/soul/validate", json={"content": content}).json()
        assert body["valid"] is True
        assert any("empty" in w for w in body["warnings"])


class TestDraftFlow:
    def test_generate_then_review(self, owner, seeded):
        owner.put(f"/api/nonprofits/{owner.nonprofit_id}/soul", json={"content": SOUL})
        r = owner.post(
            f"/api/nonprofits/{owner.nonprofit_id}/drafts/generate",
            json={"match_id": seeded["match_id"]},
        )
        assert r.status_code == 200, r.text
        drafts = r.json()
        assert drafts, "expected at least one draft"
        assert all(d["status"] == STATUS_NEEDS_REVIEW for d in drafts)

        listed = owner.get(
            f"/api/nonprofits/{owner.nonprofit_id}/drafts?match_id={seeded['match_id']}"
        ).json()
        assert len(listed) == len(drafts)

    def test_regeneration_does_not_duplicate(self, owner, seeded):
        owner.put(f"/api/nonprofits/{owner.nonprofit_id}/soul", json={"content": SOUL})
        first = owner.post(
            f"/api/nonprofits/{owner.nonprofit_id}/drafts/generate",
            json={"match_id": seeded["match_id"]},
        ).json()
        owner.post(
            f"/api/nonprofits/{owner.nonprofit_id}/drafts/generate",
            json={"match_id": seeded["match_id"]},
        )
        after = owner.get(
            f"/api/nonprofits/{owner.nonprofit_id}/drafts?match_id={seeded['match_id']}"
        ).json()
        assert len(after) == len(first), "regeneration must update in place"

    def test_draft_missing_match_404(self, owner, seeded):
        owner.put(f"/api/nonprofits/{owner.nonprofit_id}/soul", json={"content": SOUL})
        r = owner.post(
            f"/api/nonprofits/{owner.nonprofit_id}/drafts/generate",
            json={"match_id": 999999},
        )
        assert r.status_code == 404

    def test_generate_requires_soul(self, owner, seeded):
        r = owner.post(
            f"/api/nonprofits/{owner.nonprofit_id}/drafts/generate",
            json={"match_id": seeded["match_id"]},
        )
        assert r.status_code == 422


@pytest.mark.skipif(
    not os.environ.get("RUN_EMBEDDING_TESTS", "1") == "1",
    reason="embedding tests disabled",
)
class TestScoringPipeline:
    """The real acceptance path: score a grant for a WI nonprofit end to end."""

    def test_scored_match_persists_and_ranks(self, owner, tmp_path, monkeypatch):
        try:
            import sentence_transformers  # noqa: F401
        except ImportError:
            pytest.skip("sentence-transformers not installed")

        from hunter.scorer import Scorer

        soul_path = tmp_path / "soul.md"
        soul_path.write_text(SOUL)
        monkeypatch.setenv("INNER_COURT_PATH", str(soul_path))

        soul = parse_soul(SOUL)
        scorer = Scorer(soul)

        with hunter_db.session_scope() as session:
            np_row = session.get(NonprofitModel, owner.nonprofit_id)
            np_row.state = "WI"
            session.flush()

            wi = Grant(
                title=WI_GRANT, agency="WI Fund", description=WI_GRANT,
                source="state_WI", state_code="WI", dedupe_hash="h1",
            )
            unrelated = Grant(
                title="Semiconductor Substrate Research Grant",
                description="Gallium nitride physics research.",
                source="federal", dedupe_hash="h2",
            )
            session.add_all([wi, unrelated])
            session.flush()

            for grant, breakdown in scorer.score_many([wi, unrelated]):
                session.add(
                    Match(
                        nonprofit_id=np_row.id,
                        grant_id=grant.id,
                        score=breakdown.score,
                        status=STATUS_NEEDS_REVIEW,
                        rationale=breakdown.as_rationale(),
                        similarity=breakdown.similarity,
                        state_boost=breakdown.state_boost,
                    )
                )
            np_id = np_row.id

        items = owner.get(f"/api/nonprofits/{np_id}/matches").json()["items"]
        assert len(items) == 2
        assert items[0]["grant"]["state_code"] == "WI", "the WI grant must rank first"
        assert items[0]["score"] > items[1]["score"]
        assert items[0]["rationale"]["state_boost"] == 20.0
        assert items[0]["rationale"]["model"]

    def test_excluded_match_is_hidden_from_inbox(self, owner, seeded):
        with hunter_db.session_scope() as session:
            m = session.get(Match, seeded["match_id"])
            m.excluded = True
        body = owner.get(
            f"/api/nonprofits/{seeded['nonprofit_id']}/matches"
        ).json()
        assert body["total"] == 0, "an excluded match must not appear in the inbox"