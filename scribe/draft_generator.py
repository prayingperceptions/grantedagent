"""Turn a scored match into reviewable drafts.

The Scribe's contract:

* **Never invent a fact.** The context is assembled only from the soul file and
  the stored grant record. Anything absent renders as
  ``[NEEDS HUMAN INPUT: field]`` and is recorded in ``missing_inputs``.
* **Always link the official source.** Each body carries the grant's ``url`` so
  a reviewer verifies rather than trusts.
* **Always NEEDS_REVIEW.** A generated draft is a starting point for a human;
  nothing is auto-approved or submitted.

``generate_for_match`` writes one :class:`~hunter.models.Draft` per requested
kind. Generation is deterministic - the same soul and grant produce the same
text, which is what makes the drafts diffable across regenerations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date
from typing import Any, Iterable, Sequence

from sqlalchemy.orm import Session

from hunter.models import STATUS_NEEDS_REVIEW, Draft, Match
from inner_court.loader import Soul
from scribe import templater

logger = logging.getLogger("scribe.draft_generator")

DEFAULT_KINDS: tuple[str, ...] = ("loi", "need_statement", "budget_narrative")


class DraftError(RuntimeError):
    """Generation failed in a way the caller should surface."""


@dataclass
class GeneratedDraft:
    kind: str
    body: str
    missing: list[str]
    template_used: str


# ---------------------------------------------------------------------------
# Context assembly
# ---------------------------------------------------------------------------


def _format_amount(value: Any) -> str:
    try:
        amount = float(value)
    except (TypeError, ValueError):
        return ""
    if amount <= 0:
        return ""
    return f"${amount:,.0f}"


def _deadline_line(deadline: date | None) -> str:
    if deadline is None:
        return ""
    return f"Deadline: {deadline.isoformat()}\n"


def _amount_line(amount_min: Any, amount_max: Any) -> str:
    low, high = _format_amount(amount_min), _format_amount(amount_max)
    if low and high and low != high:
        return f"{low} – {high}"
    return high or low


def build_context(soul: Soul, grant: Any) -> dict[str, Any]:
    """Assemble the Jinja context from soul + grant. No inference, no filling.

    Every value is either present in an input or left absent so the template can
    mark it as needing human input. Blank boilerplate is treated as absent: a
    template that ships empty must read as a to-do, not as finished prose.
    """
    np = soul.nonprofit
    identity = dict(soul.raw.get("nonprofit") or {}) if isinstance(soul.raw, dict) else {}

    nonprofit_ctx: dict[str, Any] = {
        "name": np.name,
        "ein": np.ein,
        "mission": np.mission,
        "location": {
            "city": np.city,
            "state": np.state,
            "zip": np.zip,
            "country": np.country,
        },
        "populations_served": list(np.populations_served),
        "populations_served_list": ", ".join(np.populations_served),
        "focus_areas": list(np.focus_areas),
        "focus_areas_list": ", ".join(np.focus_areas),
        "past_grants": list(np.past_grants),
        "location_line": np.location_line,
    }

    # Optional identity fields: present only when the soul declares them, so the
    # template marks them missing rather than the Scribe guessing a signatory.
    for key in ("signatory_name", "signatory_title", "total_budget", "founded_year", "website"):
        if identity.get(key):
            nonprofit_ctx[key] = identity[key]
    nonprofit_ctx["total_budget_line"] = _format_amount(identity.get("total_budget"))

    # Blank boilerplate is omitted from `templates`, which makes `{{ templates.x }}`
    # resolve to Undefined and render as [NEEDS HUMAN INPUT: templates.x].
    templates_ctx = {k: v for k, v in soul.templates.items() if str(v).strip()}

    grant_ctx: dict[str, Any] = {
        "title": getattr(grant, "title", "") or "",
        "agency": getattr(grant, "agency", None) or "",
        "url": getattr(grant, "url", None) or "",
        "source": getattr(grant, "source", None) or "",
        "state_code": getattr(grant, "state_code", None) or "",
        "description": getattr(grant, "description", None) or "",
        "deadline": getattr(grant, "deadline", None),
        "deadline_line": _deadline_line(getattr(grant, "deadline", None)),
        "amount_line": _amount_line(
            getattr(grant, "amount_min", None), getattr(grant, "amount_max", None)
        ),
    }

    # A salutation is a nicety, not a fact: fall back to a neutral greeting that
    # is always true rather than inventing a program officer's name.
    grant_ctx["funder_salutation"] = (
        f"{grant_ctx['agency']} team" if grant_ctx["agency"] else "Grantmaking team"
    )

    return {
        "nonprofit": nonprofit_ctx,
        "grant": grant_ctx,
        "templates": templates_ctx,
        "soul": soul.as_template_context(),
    }


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------


def generate(
    soul: Soul,
    grant: Any,
    kinds: Sequence[str] = DEFAULT_KINDS,
) -> list[GeneratedDraft]:
    """Render the requested draft kinds for one grant. Pure; writes nothing."""
    context = build_context(soul, grant)
    out: list[GeneratedDraft] = []

    for kind in kinds:
        try:
            result = templater.render(kind, context, soul_templates=soul.templates)
        except KeyError as exc:
            raise DraftError(str(exc)) from exc
        except ValueError as exc:
            raise DraftError(str(exc)) from exc

        body = templater.with_source_footer(result.body, context["grant"].get("url"))
        out.append(
            GeneratedDraft(
                kind=kind,
                body=body,
                missing=result.missing,
                template_used=result.template_used,
            )
        )
    return out


def generate_for_match(
    session: Session,
    match: Match,
    soul: Soul,
    *,
    kinds: Sequence[str] = DEFAULT_KINDS,
    replace: bool = True,
) -> list[Draft]:
    """Generate and persist drafts for a match, all at NEEDS_REVIEW.

    ``replace`` regenerates existing drafts of the same kind rather than
    duplicating them, so a soul edit followed by a re-run updates in place.
    """
    grant = match.grant
    if grant is None:
        raise DraftError(f"match {match.id} has no grant loaded")

    generated = generate(soul, grant, kinds)

    existing: dict[str, Draft] = {}
    if replace:
        existing = {
            d.kind: d
            for d in session.query(Draft).filter(Draft.match_id == match.id).all()
        }

    persisted: list[Draft] = []
    for item in generated:
        row = existing.get(item.kind)
        if row is None:
            row = Draft(match_id=match.id, kind=item.kind)
            session.add(row)

        row.title = f"{item.kind.replace('_', ' ').title()} — {grant.title[:120]}"
        row.body = item.body
        row.source_url = grant.url
        row.status = STATUS_NEEDS_REVIEW
        row.missing_inputs = item.missing
        row.template_used = item.template_used
        row.generator = "scribe.draft_generator"

        persisted.append(row)

    session.flush()
    logger.info(
        "scribe: generated %d draft(s) for match %s (%d need human input)",
        len(persisted),
        match.id,
        sum(1 for d in persisted if d.missing_inputs),
    )
    return persisted


def missing_input_summary(drafts: Iterable[Draft]) -> dict[str, list[str]]:
    """Per-draft list of unresolved fields, for the review UI."""
    return {
        f"{d.kind}#{d.id}": list(d.missing_inputs or []) for d in drafts if d.missing_inputs
    }


__all__ = [
    "DEFAULT_KINDS",
    "DraftError",
    "GeneratedDraft",
    "build_context",
    "generate",
    "generate_for_match",
    "missing_input_summary",
]