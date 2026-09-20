"""Score grants against a nonprofit's soul.

Scoring is a rule layer on top of a semantic similarity layer:

    score = calibrated_similarity * 100 + state_boost

The calibration matters. Raw MiniLM cosine similarity for genuinely good
grant/nonprofit pairs lands around 0.45-0.60, and unrelated pairs around
0.03-0.15. Multiplying raw cosine by 100 would cap a strong California match
near 57 and no grant would ever clear the ">85" bar. So we map cosine onto a
0-100 scale through an explicit window derived from measured behaviour of
all-MiniLM-L6-v2 on grant text (:data:`SIM_FLOOR` / :data:`SIM_CEIL`).

Boosts are applied in *score points* on the 0-100 scale:

    +20  the grant is scoped to the nonprofit's own state
    +10  the grant is national (open to any US location)
    -1.0 the grant trips an exclusion; it is filtered out entirely

There is no state hardcode anywhere in this module: the state comes from the
soul's ``matching_rules`` and the grant's ``state_code``, so it behaves the same
for CA, WI, TX or any other of the 50 states.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from hunter.config import get_settings
from hunter.models import SOURCE_NATIONAL_FOUNDATION, SOURCE_STATE_PREFIX
from inner_court.loader import Soul
from inner_court.states import NATIONAL

logger = logging.getLogger("hunter.scorer")

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

# Calibration window for all-MiniLM-L6-v2 on grant/nonprofit prose. Measured
# against real pairs: strong matches ~0.70, topical-but-wrong-state ~0.56,
# unrelated ~0.03-0.13. Cosine <= floor maps to 0, >= ceiling maps to
# CALIBRATION_MAX.
SIM_FLOOR = 0.20
SIM_CEIL = 0.72

# Semantic quality contributes at most this much, leaving the remaining points
# for the location boost. If quality could reach 100 on its own, a strong match
# would saturate and the state boost would silently stop discriminating.
CALIBRATION_MAX = 80.0

STATE_BOOST_MATCH = 20.0
STATE_BOOST_NATIONAL = 10.0
EXCLUDE_SCORE = -1.0

# A record with no real description cannot be matched meaningfully: the semantic
# score would rest on the title alone, and vague navigation titles ("What We
# Fund", "Donor-Advised Funds") resemble every nonprofit equally. Those records
# are capped rather than allowed to top the inbox, and flagged so the UI can ask
# for enrichment.
MIN_DESCRIPTION_CHARS = 80
LOW_CONTENT_CAP = 55.0

MAX_SCORE = 100.0


@dataclass
class ScoreBreakdown:
    """Why a grant scored what it scored. Persisted on the match row."""

    score: float
    similarity: float
    calibrated: float
    state_boost: float
    excluded: bool
    exclusion_hits: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    state_match: str = "none"
    low_content: bool = False

    def as_rationale(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 2),
            "similarity": round(self.similarity, 4),
            "calibrated": round(self.calibrated, 2),
            "state_boost": self.state_boost,
            "state_match": self.state_match,
            "excluded": self.excluded,
            "low_content": self.low_content,
            "exclusion_hits": list(self.exclusion_hits),
            "reasons": list(self.reasons),
            "model": MODEL_NAME,
        }


class ScorerUnavailable(RuntimeError):
    """The embedding model could not be loaded."""


def calibrate(
    cosine: float,
    *,
    floor: float = SIM_FLOOR,
    ceiling: float = SIM_CEIL,
    out_max: float = CALIBRATION_MAX,
) -> float:
    """Map a cosine similarity onto ``0..out_max``. Clamped, never negative."""
    if ceiling <= floor:
        raise ValueError("ceiling must be greater than floor")
    scaled = (cosine - floor) / (ceiling - floor)
    return max(0.0, min(1.0, scaled)) * out_max


def nonprofit_profile_text(soul: Soul) -> str:
    """The text we embed for a nonprofit.

    Location is deliberately included: a funder's own description of who may
    apply is usually where state scope appears, so having the nonprofit's state
    in their vector helps surface in-state and national programmes.
    """
    np = soul.nonprofit
    rules = soul.matching_rules
    lines = [
        np.name,
        np.mission,
        f"Focus areas: {', '.join(np.focus_areas)}" if np.focus_areas else "",
        f"Populations served: {', '.join(np.populations_served)}" if np.populations_served else "",
        f"Located in {np.city}, {np.state} {np.zip} {np.country}".strip(),
        f"Accepts funding in: {', '.join(rules.states)}" if rules.states else "",
    ]
    return "\n".join(line for line in lines if line)


def grant_text(title: str, agency: str | None, description: str | None) -> str:
    parts = [title or ""]
    if agency:
        parts.append(str(agency))
    if description:
        parts.append(str(description))
    return "\n".join(p for p in parts if p)


class Scorer:
    """Embeds grants and scores them against one soul.

    The model is loaded lazily and cached at class level: loading MiniLM costs
    a few hundred milliseconds and a few hundred MB, so a scorer should be built
    once and reused across a hunt.
    """

    _model: Any = None

    def __init__(
        self,
        soul: Soul,
        *,
        model_name: str | None = None,
        model: Any = None,
        sim_floor: float | None = None,
        sim_ceil: float | None = None,
        min_description_chars: int | None = None,
    ) -> None:
        cfg = get_settings()
        self.soul = soul
        self.model_name = model_name or cfg.scorer_model
        self.sim_floor = cfg.scorer_sim_floor if sim_floor is None else sim_floor
        self.sim_ceil = cfg.scorer_sim_ceil if sim_ceil is None else sim_ceil
        self.min_description_chars = (
            cfg.scorer_min_description_chars
            if min_description_chars is None
            else min_description_chars
        )
        if model is not None:
            self._model = model
        self._profile_text = nonprofit_profile_text(soul)

    # -- model ---------------------------------------------------------------

    def _load_model(self) -> Any:
        if Scorer._model is None:
            try:
                from sentence_transformers import SentenceTransformer
            except ImportError as exc:  # pragma: no cover - depends on install
                raise ScorerUnavailable(
                    "sentence-transformers is not installed. "
                    "Install it with `uv pip install sentence-transformers`."
                ) from exc
            logger.info("scorer: loading %s", self.model_name)
            Scorer._model = SentenceTransformer(self.model_name)
        return Scorer._model

    @property
    def model(self) -> Any:
        return self._model if self._model is not None else self._load_model()

    def embed(self, texts: Sequence[str]) -> Any:
        """Normalised embeddings, so cosine is a plain dot product."""
        if not texts:
            import numpy as np

            return np.zeros((0, self.dimension), dtype="float32")
        return self.model.encode(
            list(texts), normalize_embeddings=True, convert_to_numpy=True, show_progress_bar=False
        )

    @property
    def dimension(self) -> int:
        model = self.model
        # Newer sentence-transformers renamed this; prefer the current name.
        getter = getattr(model, "get_embedding_dimension", None) or getattr(
            model, "get_sentence_embedding_dimension"
        )
        return int(getter())

    def embed_profile(self) -> list[float]:
        return self.embed([self._profile_text])[0].tolist()

    # -- scoring -------------------------------------------------------------

    def score(
        self,
        title: str,
        *,
        agency: str | None = None,
        description: str | None = None,
        state_code: str | None = None,
        source: str | None = None,
        similarity: float | None = None,
        profile_embedding: Any = None,
    ) -> ScoreBreakdown:
        """Score one grant. Pass ``similarity`` to reuse a precomputed value."""
        text = grant_text(title, agency, description)

        if similarity is None:
            if profile_embedding is None:
                profile_embedding = self.embed([self._profile_text])[0]
            import numpy as np

            v = self.embed([text])[0]
            similarity = float(np.dot(profile_embedding, v))

        return self.score_from_similarity(
            similarity,
            title=title,
            description=description,
            state_code=state_code,
            source=source,
        )

    def score_from_similarity(
        self,
        similarity: float,
        *,
        title: str = "",
        description: str | None = None,
        state_code: str | None = None,
        source: str | None = None,
    ) -> ScoreBreakdown:
        reasons: list[str] = []

        hits = self._exclusion_hits(title, description, agency=None)
        if hits:
            return ScoreBreakdown(
                score=EXCLUDE_SCORE,
                similarity=float(similarity),
                calibrated=0.0,
                state_boost=0.0,
                excluded=True,
                exclusion_hits=hits,
                reasons=(f"excluded by rule: matched {', '.join(hits)}",),
                state_match="excluded",
            )

        calibrated = calibrate(
            float(similarity), floor=self.sim_floor, ceiling=self.sim_ceil
        )
        boost, state_match = self._state_boost(state_code, source)
        if state_match == "in_state":
            reasons.append(f"scoped to {state_code}")
        elif state_match == "national":
            reasons.append("national programme")
        else:
            reasons.append("no location advantage")

        score = calibrated + boost

        # A thin record is capped so it cannot outrank a genuinely described
        # opportunity purely on location.
        low_content = (
            len((description or "").strip()) < self.min_description_chars
        )
        if low_content:
            score = min(score, LOW_CONTENT_CAP)
            reasons.append(
                f"limited description ({len((description or '').strip())} chars): "
                f"capped at {LOW_CONTENT_CAP:.0f} pending enrichment"
            )

        score = min(MAX_SCORE, score)
        reasons.append(
            f"semantic {similarity:.2f} -> {calibrated:.0f}/100, +{boost:.0f} location"
        )

        return ScoreBreakdown(
            score=score,
            similarity=float(similarity),
            calibrated=calibrated,
            state_boost=boost,
            excluded=False,
            reasons=tuple(reasons),
            state_match=state_match,
            low_content=low_content,
        )

    # -- rules ---------------------------------------------------------------

    def _exclusion_hits(self, title: str, description: str | None, agency: str | None) -> tuple[str, ...]:
        exclusions = self.soul.matching_rules.exclusions
        if not exclusions:
            return ()
        haystack = " ".join(str(p) for p in (title, agency, description) if p).casefold()
        return tuple(x for x in exclusions if x.casefold() in haystack)

    def _state_boost(self, state_code: str | None, source: str | None) -> tuple[float, str]:
        """Location advantage, derived entirely from the soul's rules.

        A grant is in-state when *either* its ``state_code`` matches the
        nonprofit's home state *or* its source encodes that state (``state_CA``).
        A grant is national when its source is a national foundation, or when
        it carries no state scope at all and the soul accepts national funding.
        """
        rules = self.soul.matching_rules
        home = self.soul.nonprofit.state
        code = (state_code or "").strip().upper()

        # In-state: explicit state_code, or a state_XX source with no state_code.
        effective = code
        if not effective and source and str(source).startswith(SOURCE_STATE_PREFIX):
            effective = str(source)[len(SOURCE_STATE_PREFIX):].strip().upper()

        if effective and (effective == home or rules.covers_state(effective)):
            return STATE_BOOST_MATCH, "in_state"

        is_national_source = source == SOURCE_NATIONAL_FOUNDATION
        # A federal grant with no state scope is nationally available.
        unscoped_federal = not effective and source is not None and source != ""
        if (is_national_source or unscoped_federal) and rules.allows_national():
            return STATE_BOOST_NATIONAL, "national"

        return 0.0, "none"

    # -- batch ---------------------------------------------------------------

    def score_many(self, grants: Iterable[Any]) -> list[tuple[Any, ScoreBreakdown]]:
        """Score an iterable of grant-like objects in one encode call."""
        items = list(grants)
        if not items:
            return []

        texts = [
            grant_text(
                getattr(g, "title", "") or "",
                getattr(g, "agency", None),
                getattr(g, "description", None),
            )
            for g in items
        ]
        import numpy as np

        profile = self.embed([self._profile_text])[0]
        vectors = self.embed(texts)
        sims = np.dot(vectors, profile)

        out: list[tuple[Any, ScoreBreakdown]] = []
        for grant, sim in zip(items, sims):
            out.append(
                (
                    grant,
                    self.score_from_similarity(
                        float(sim),
                        title=getattr(grant, "title", "") or "",
                        description=getattr(grant, "description", None),
                        state_code=getattr(grant, "state_code", None),
                        source=getattr(grant, "source", None),
                    ),
                )
            )
        return out


__all__ = [
    "Scorer",
    "ScoreBreakdown",
    "ScorerUnavailable",
    "calibrate",
    "nonprofit_profile_text",
    "grant_text",
    "MODEL_NAME",
    "SIM_FLOOR",
    "SIM_CEIL",
    "STATE_BOOST_MATCH",
    "STATE_BOOST_NATIONAL",
    "EXCLUDE_SCORE",
    "CALIBRATION_MAX",
    "MIN_DESCRIPTION_CHARS",
    "LOW_CONTENT_CAP",
]