"""Settings plumbing tests.

These guard the wiring between env vars and behaviour: a documented variable
that nothing reads is worse than no variable at all.
"""

from __future__ import annotations

from hunter.config import get_settings
from hunter.scorer import Scorer
from inner_court.loader import parse_soul, resolve_soul_path

SOUL = """
location:
  state: "WI"
matching_rules:
  states: ["WI", "national"]
nonprofit:
  name: "Anytown Coalition"
  mission: "We serve families."
"""


class _FakeModel:
    def get_embedding_dimension(self) -> int:
        return 384

    def encode(self, texts, **kwargs):
        import numpy as np

        return np.ones((len(texts), 384), dtype="float32")


class TestSettingsDefaults:
    def test_documented_defaults(self):
        s = get_settings()
        assert s.scorer_model == "sentence-transformers/all-MiniLM-L6-v2"
        assert s.scorer_sim_floor == 0.20
        assert s.scorer_sim_ceil == 0.72
        assert s.scorer_min_description_chars == 80

    def test_cors_origin_list_parses(self, monkeypatch):
        monkeypatch.setenv("CORS_ORIGINS", "http://a.test, http://b.test ,")
        from hunter.config import reload_settings

        assert reload_settings().cors_origin_list == ["http://a.test", "http://b.test"]

    def test_states_filter_all_is_nationwide(self, monkeypatch):
        from hunter.config import reload_settings

        monkeypatch.setenv("STATES_FILTER", "ALL")
        assert reload_settings().is_nationwide is True
        monkeypatch.setenv("STATES_FILTER", "WI, mn")
        s = reload_settings()
        assert s.state_codes == ["WI", "MN"]
        assert s.is_nationwide is False


class TestScorerReadsSettings:
    def test_model_name_from_env(self, monkeypatch):
        monkeypatch.setenv("SCORER_MODEL", "some/other-model")
        from hunter.config import reload_settings

        reload_settings()
        assert Scorer(parse_soul(SOUL), model=_FakeModel()).model_name == "some/other-model"

    def test_sim_window_from_env(self, monkeypatch):
        monkeypatch.setenv("SCORER_SIM_FLOOR", "0.05")
        monkeypatch.setenv("SCORER_SIM_CEIL", "0.60")
        from hunter.config import reload_settings

        reload_settings()
        s = Scorer(parse_soul(SOUL), model=_FakeModel())
        assert s.sim_floor == 0.05
        assert s.sim_ceil == 0.60

    def test_tightening_the_floor_lowers_scores(self, monkeypatch):
        """The floor must actually change behaviour, not just be stored."""
        from hunter.config import reload_settings

        monkeypatch.setenv("SCORER_SIM_FLOOR", "0.10")
        monkeypatch.setenv("SCORER_SIM_CEIL", "0.72")
        reload_settings()
        loose = Scorer(parse_soul(SOUL), model=_FakeModel())
        loose_score = loose.score_from_similarity(
            0.40, title="t", description="d" * 200, source="state_WI"
        ).score

        monkeypatch.setenv("SCORER_SIM_FLOOR", "0.35")
        reload_settings()
        tight = Scorer(parse_soul(SOUL), model=_FakeModel())
        tight_score = tight.score_from_similarity(
            0.40, title="t", description="d" * 200, source="state_WI"
        ).score
        assert tight_score < loose_score

    def test_min_description_chars_from_env(self, monkeypatch):
        monkeypatch.setenv("SCORER_MIN_DESCRIPTION_CHARS", "500")
        from hunter.config import reload_settings

        reload_settings()
        s = Scorer(parse_soul(SOUL), model=_FakeModel())
        assert s.min_description_chars == 500
        b = s.score_from_similarity(0.9, title="t", description="d" * 200, source="state_WI")
        assert b.low_content is True

    def test_explicit_argument_overrides_settings(self, monkeypatch):
        monkeypatch.setenv("SCORER_SIM_FLOOR", "0.05")
        from hunter.config import reload_settings

        reload_settings()
        s = Scorer(parse_soul(SOUL), model=_FakeModel(), sim_floor=0.3)
        assert s.sim_floor == 0.3


class TestSoulPathFromSettings:
    def test_inner_court_path_respected(self, tmp_path, monkeypatch):
        monkeypatch.setenv("INNER_COURT_PATH", str(tmp_path / "soul.md"))
        from hunter.config import reload_settings

        reload_settings()
        assert resolve_soul_path() == tmp_path / "soul.md"

    def test_explicit_argument_wins(self, tmp_path, monkeypatch):
        monkeypatch.setenv("INNER_COURT_PATH", str(tmp_path / "env.md"))
        from hunter.config import reload_settings

        reload_settings()
        assert resolve_soul_path(tmp_path / "explicit.md") == tmp_path / "explicit.md"

    def test_defaults_to_cwd_soul_md(self, monkeypatch):
        monkeypatch.delenv("INNER_COURT_PATH", raising=False)
        from hunter.config import reload_settings

        reload_settings()
        assert resolve_soul_path().name == "soul.md"