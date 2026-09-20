"""Scorer tests.

The pure-logic tests run everywhere. The embedding tests load MiniLM and are
skipped when ``sentence-transformers`` is unavailable, so the offline suite
stays fast.
"""

from __future__ import annotations

import pytest

from hunter.scorer import (
    EXCLUDE_SCORE,
    LOW_CONTENT_CAP,
    MAX_SCORE,
    STATE_BOOST_MATCH,
    STATE_BOOST_NATIONAL,
    Scorer,
    calibrate,
    grant_text,
    nonprofit_profile_text,
)
from inner_court.loader import parse_soul

try:
    import sentence_transformers as _st  # noqa: F401

    HAS_ST = True
except ImportError:  # pragma: no cover - depends on install
    HAS_ST = False

requires_st = pytest.mark.skipif(not HAS_ST, reason="sentence-transformers not installed")


SOUL = """
location:
  city: "Anytown"
  state: "CA"
  zip: "90210"
matching_rules:
  states: ["CA", "national"]
nonprofit:
  name: "Anytown Community Coalition"
  mission: "We improve health and economic outcomes for families through direct services and community partnership."
  populations_served: ["low-income families", "youth", "seniors"]
  focus_areas: ["community health", "food security", "youth development"]
"""

TX_SOUL = SOUL.replace('state: "CA"', 'state: "TX"').replace('["CA", "national"]', '["TX", "national"]')

CA_GRANT = (
    "Community Health Grant Program: funding for California nonprofits expanding "
    "primary care access for low-income families and youth in underserved communities."
)
TX_GRANT = (
    "Texas Community Health Grant Program: funding for Texas nonprofits expanding "
    "primary care access for low-income families in Harris County."
)
NATIONAL_GRANT = (
    "National Community Health Grant: open to nonprofits in all 50 states, funding "
    "primary care and food security programs for low-income families."
)
UNRELATED_GRANT = (
    "Advanced Semiconductor Materials Research Grant for university physics "
    "departments studying gallium nitride substrates at scale."
)


class TestCalibration:
    def test_clamps_below_floor_to_zero(self):
        assert calibrate(0.05) == 0.0
        assert calibrate(-0.5) == 0.0

    def test_clamps_above_ceiling_to_max(self):
        assert calibrate(0.99) == 80.0

    def test_monotonic(self):
        values = [calibrate(x / 100) for x in range(100)]
        assert values == sorted(values)

    def test_leaves_headroom_for_boost(self):
        """Quality alone must not reach 100, or the state boost stops mattering."""
        assert calibrate(1.0) < MAX_SCORE

    def test_rejects_inverted_window(self):
        with pytest.raises(ValueError):
            calibrate(0.5, floor=0.9, ceiling=0.1)


class TestProfileText:
    def test_includes_state_and_mission(self):
        text = nonprofit_profile_text(parse_soul(SOUL))
        assert "Anytown Community Coalition" in text
        assert "CA" in text
        assert "community health" in text

    def test_grant_text_combines_fields(self):
        assert "Title" in grant_text("Title", "Agency", "Description")
        assert grant_text("Only Title", None, None) == "Only Title"


class TestRulesWithoutEmbeddings:
    """Rule-layer behaviour, driven by an explicit similarity."""

    def test_exclusion_wins_over_high_similarity(self):
        soul = parse_soul(SOUL.replace('exclusions: []', "").replace(
            'states: ["CA", "national"]',
            'states: ["CA", "national"]\n  exclusions: ["for-profit"]'))
        s = Scorer(soul, model=_FakeModel())
        b = s.score_from_similarity(0.99, title="Health grant for for-profit clinics", source="state_CA")
        assert b.excluded is True
        assert b.score == EXCLUDE_SCORE

    def test_no_state_hardcode_wi_behaves_like_ca(self):
        """The same grant must boost for whichever state the soul declares."""
        for code in ("CA", "WI", "TX", "NY"):
            soul = parse_soul(SOUL.replace('state: "CA"', f'state: "{code}"').replace(
                '["CA", "national"]', f'["{code}", "national"]'))
            s = Scorer(soul, model=_FakeModel())
            boost, match = s._state_boost(None, f"state_{code}")
            assert boost == STATE_BOOST_MATCH, code
            assert match == "in_state", code

    def test_out_of_state_state_source_gets_no_boost(self):
        s = Scorer(parse_soul(SOUL), model=_FakeModel())
        boost, match = s._state_boost(None, "state_OH")
        assert boost == 0.0
        assert match == "none"

    def test_explicit_state_code_matches(self):
        s = Scorer(parse_soul(SOUL), model=_FakeModel())
        assert s._state_boost("CA", "state_CA")[0] == STATE_BOOST_MATCH

    def test_national_foundation_gets_national_boost(self):
        s = Scorer(parse_soul(SOUL), model=_FakeModel())
        boost, match = s._state_boost(None, "national_foundation")
        assert boost == STATE_BOOST_NATIONAL
        assert match == "national"

    def test_unscoped_federal_is_national(self):
        s = Scorer(parse_soul(SOUL), model=_FakeModel())
        assert s._state_boost(None, "federal")[1] == "national"

    def test_national_boost_denied_when_soul_excludes_national(self):
        soul = parse_soul(SOUL.replace('["CA", "national"]', '["CA"]'))
        s = Scorer(soul, model=_FakeModel())
        assert s._state_boost(None, "national_foundation")[0] == 0.0

    def test_score_never_exceeds_max(self):
        s = Scorer(parse_soul(SOUL), model=_FakeModel())
        b = s.score_from_similarity(1.0, title="Health", state_code="CA", source="state_CA")
        assert b.score <= MAX_SCORE

    def test_score_never_negative_except_exclusion(self):
        s = Scorer(parse_soul(SOUL), model=_FakeModel())
        b = s.score_from_similarity(-1.0, title="Anything", source="federal")
        assert b.score >= 0.0

    def test_low_content_record_cannot_top_the_inbox(self):
        """A description-less record must not outrank a properly described one.

        On live data 97% of foundation rows have no description, so matching
        would otherwise run on the title alone and vague nav titles ("What We
        Fund") would head every shortlist.
        """
        s = Scorer(parse_soul(SOUL), model=_FakeModel())
        thin = s.score_from_similarity(0.95, title="What We Fund", description=None, source="state_CA")
        rich = s.score_from_similarity(
            0.55, title="Community Health Grant", description="x" * 400, source="state_CA"
        )
        assert thin.low_content is True
        assert rich.low_content is False
        assert thin.score <= LOW_CONTENT_CAP
        assert rich.score > thin.score

    def test_low_content_flag_is_in_the_rationale(self):
        s = Scorer(parse_soul(SOUL), model=_FakeModel())
        b = s.score_from_similarity(0.9, title="Funding Opportunities", description="", source="state_CA")
        assert b.as_rationale()["low_content"] is True
        assert any("limited description" in r for r in b.reasons)

    def test_well_described_record_is_not_capped(self):
        s = Scorer(parse_soul(SOUL), model=_FakeModel())
        b = s.score_from_similarity(
            0.9, title="Health Grant", description="y" * 200, source="state_CA"
        )
        assert b.low_content is False
        assert b.score > LOW_CONTENT_CAP

    def test_docs_with_real_descriptions_are_unaffected(self):
        """The cap must not suppress a well-described grant."""
        soul = parse_soul(SOUL)
        s = Scorer(soul, model=_FakeModel())
        b = s.score_from_similarity(
            0.703,
            title="Community Health Grant",
            description="A detailed programme description " * 6,
            state_code="CA",
            source="state_CA",
        )
        assert b.low_content is False
        assert b.score > 85

    def test_rationale_is_auditable(self):
        s = Scorer(parse_soul(SOUL), model=_FakeModel())
        b = s.score_from_similarity(0.6, title="Health", state_code="CA", source="state_CA")
        r = b.as_rationale()
        assert r["state_boost"] == STATE_BOOST_MATCH
        assert "model" in r
        assert r["reasons"]


class _FakeModel:
    """Deterministic stand-in so rule tests need no ML download."""

    def get_sentence_embedding_dimension(self) -> int:
        return 384

    def encode(self, texts, **kwargs):
        import numpy as np

        n = len(texts)
        return np.ones((n, 384), dtype="float32") / (384**0.5)


@requires_st
class TestScoringWithRealEmbeddings:
    """The acceptance criteria, measured against the real model."""

    @pytest.fixture(scope="class")
    def ca_scorer(self):
        return Scorer(parse_soul(SOUL))

    def _score(self, scorer, text, state_code=None, source=None):
        import numpy as np

        profile = scorer.embed([scorer._profile_text])[0]
        sim = float(np.dot(scorer.embed([text])[0], profile))
        # Pass the text as the description too: the acceptance fixtures describe
        # real opportunities, and the low-content cap is tested separately.
        return scorer.score_from_similarity(
            sim, title=text, description=text, state_code=state_code, source=source
        )

    def test_model_dimension_matches_schema(self, ca_scorer):
        from hunter.models import EMBEDDING_DIM

        assert ca_scorer.dimension == EMBEDDING_DIM == 384

    def test_in_state_grant_scores_above_85(self, ca_scorer):
        b = self._score(ca_scorer, CA_GRANT, "CA", "state_CA")
        assert b.score > 85, f"expected >85, got {b.score:.1f}"

    def test_out_of_state_grant_scores_lower(self, ca_scorer):
        in_state = self._score(ca_scorer, CA_GRANT, "CA", "state_CA").score
        out_state = self._score(ca_scorer, CA_GRANT, None, "state_TX").score
        assert out_state < in_state

    def test_national_grant_gets_equal_location_boost(self, ca_scorer):
        """National funding must carry the same boost for every state.

        The *rule* is location-neutral. Similarity can still differ by a point or
        two because the nonprofit's own state is part of their profile text - that
        is a semantic artifact, not a state-specific code path.
        """
        tx_scorer = Scorer(parse_soul(TX_SOUL))
        ca = self._score(ca_scorer, NATIONAL_GRANT, None, "federal")
        tx = self._score(tx_scorer, NATIONAL_GRANT, None, "federal")
        assert ca.state_boost == tx.state_boost == STATE_BOOST_NATIONAL
        assert ca.state_match == tx.state_match == "national"
        assert abs(ca.score - tx.score) < 10, "national funding must not strongly favour a state"

    def test_national_grant_is_high_for_both_states(self, ca_scorer):
        """The acceptance claim: national funding ranks well in either state."""
        tx_scorer = Scorer(parse_soul(TX_SOUL))
        ca = self._score(ca_scorer, NATIONAL_GRANT, None, "federal").score
        tx = self._score(tx_scorer, NATIONAL_GRANT, None, "federal").score
        assert ca > 70, ca
        assert tx > 70, tx

    def test_national_grant_is_high(self, ca_scorer):
        """National programmes rank well above unrelated ones."""
        national = self._score(ca_scorer, NATIONAL_GRANT, None, "federal").score
        unrelated = self._score(ca_scorer, UNRELATED_GRANT, None, "federal").score
        assert national > 70
        assert national - unrelated > 40

    def test_state_boost_is_visible_on_a_strong_match(self, ca_scorer):
        """A strong in-state match must outrank the same text scored nationally."""
        in_state = self._score(ca_scorer, CA_GRANT, "CA", "state_CA").score
        national = self._score(ca_scorer, CA_GRANT, None, "national_foundation").score
        assert in_state > national, "in-state funding must beat the same grant offered nationally"

    def test_unrelated_grant_is_low(self, ca_scorer):
        b = self._score(ca_scorer, UNRELATED_GRANT, None, "federal")
        assert b.score < 30

    def test_wi_nonprofit_prefers_wi_grant(self):
        """The WI case the product promises, with no WI-specific code path."""
        wi_soul = parse_soul(SOUL.replace('state: "CA"', 'state: "WI"').replace(
            '["CA", "national"]', '["WI", "national"]'))
        s = Scorer(wi_soul)
        wi_grant = (
            "Wisconsin Community Health Grant: funding for Wisconsin nonprofits "
            "expanding primary care access for low-income families and youth."
        )
        wi_score = self._score(s, wi_grant, "WI", "state_WI").score
        other_score = self._score(s, wi_grant, None, "state_CA").score
        assert wi_score > other_score
        assert wi_score > 85

    def test_score_many_returns_all(self, ca_scorer):
        class G:
            def __init__(self, t, c, s):
                self.title, self.agency, self.description = t, None, t
                self.state_code, self.source = c, s

        grants = [
            G(CA_GRANT, "CA", "state_CA"),
            G(TX_GRANT, None, "state_TX"),
            G(UNRELATED_GRANT, None, "federal"),
        ]
        out = ca_scorer.score_many(grants)
        assert len(out) == 3
        assert out[0][1].score > out[1][1].score > out[2][1].score