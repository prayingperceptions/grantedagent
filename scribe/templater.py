"""Deterministic document generation from soul templates.

The rule that shapes this module: **the Scribe never invents facts.** It only
interpolates values that are already present in the soul file or the grant
record. When a template needs something that is not there, the output carries an
explicit marker instead of plausible-sounding filler:

    [NEEDS HUMAN INPUT: nonprofit.mission]

That marker is collected into ``missing_inputs`` so the UI can show a reviewer
exactly which fields to fill before the draft is usable.

Every document ends with a link to the official opportunity page, so a reviewer
can verify the source rather than trusting the draft.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from jinja2 import Environment, TemplateSyntaxError, Undefined
from jinja2 import meta as jinja_meta

logger = logging.getLogger("scribe.templater")

MISSING_TEMPLATE = "[NEEDS HUMAN INPUT: {name}]"

DRAFT_KINDS = (
    "loi",
    "need_statement",
    "budget_narrative",
    "cover_letter",
    "executive_summary",
    "alignment_statement",
)

# Official-source disclaimer appended to every draft body.
SOURCE_FOOTER = (
    "---\n"
    "Official source: {url}\n"
    "Verify all dates, amounts, and eligibility on the funder's page before submitting."
)


class RecordingUndefined(Undefined):
    """Renders a visible marker instead of raising or blanking.

    ``Undefined`` is used (rather than ``StrictUndefined``) so one absent field
    does not abort the document: the reviewer still gets everything that *could*
    be filled, plus an explicit list of what is missing.
    """

    def __str__(self) -> str:
        return MISSING_TEMPLATE.format(name=self._undefined_name or "unknown")

    def __html__(self) -> str:
        return str(self)

    def __iter__(self):
        return iter(())

    def __len__(self) -> int:
        return 0

    def __bool__(self) -> bool:
        return False

    def __getattr__(self, name: str) -> Any:
        # Allow `{{ missing.field }}` without an AttributeError.
        if name.startswith("_"):
            raise AttributeError(name)
        return RecordingUndefined(
            hint=self._undefined_hint, obj=self._undefined_obj, name=f"{self._undefined_name}.{name}"
        )


@dataclass
class RenderResult:
    kind: str
    body: str
    missing: list[str] = field(default_factory=list)
    template_used: str = ""
    warnings: list[str] = field(default_factory=list)


def _env(undefined_cls: type[Undefined] = RecordingUndefined) -> Environment:
    return Environment(
        undefined=undefined_cls,
        autoescape=False,  # plain-text documents, not HTML
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


# ---------------------------------------------------------------------------
# Default templates. A soul file may override any of these by declaring a
# template of the same name under `templates:`.
# ---------------------------------------------------------------------------

DEFAULT_TEMPLATES: dict[str, str] = {
    "loi": """\
{{ nonprofit.name }}
{{ nonprofit.location.city }}, {{ nonprofit.location.state }} {{ nonprofit.location.zip }}

{{ grant.deadline_line }}Official source: {{ grant.url }}

Dear {{ grant.funder_salutation }},

{{ nonprofit.name }} respectfully submits this letter of inquiry regarding \
{{ grant.title }}{% if grant.agency %} ({{ grant.agency }}){% endif %}.

{{ templates.need_statement }}

{{ templates.alignment_statement }}

We would welcome the opportunity to submit a full proposal. Thank you for your \
consideration.

Sincerely,
{{ nonprofit.signatory_name }}
{{ nonprofit.signatory_title }}
{{ nonprofit.name }}
EIN: {{ nonprofit.ein }}
""",
    "need_statement": """\
Statement of Need — {{ nonprofit.name }}

{{ templates.need_statement }}

Populations served: {{ nonprofit.populations_served_list }}
Geographic focus: {{ nonprofit.location.city }}, {{ nonprofit.location.state }}
""",
    "budget_narrative": """\
Budget Narrative — {{ nonprofit.name }}

Requested amount: {{ grant.amount_line }}

{{ templates.budget_narrative }}

Total organizational budget: {{ nonprofit.total_budget_line }}
""",
    "cover_letter": """\
{{ nonprofit.name }}
EIN: {{ nonprofit.ein }}
{{ nonprofit.location_line }}

{{ grant.deadline_line }}Official source: {{ grant.url }}

Dear {{ grant.funder_salutation }},

Please find attached our application for {{ grant.title }}{% if grant.agency %}, \
administered by {{ grant.agency }}{% endif %}.

{{ nonprofit.mission }}

{{ templates.alignment_statement }}

Sincerely,
{{ nonprofit.signatory_name }}
{{ nonprofit.signatory_title }}
""",
    "executive_summary": """\
Executive Summary — {{ grant.title }}
Applicant: {{ nonprofit.name }} ({{ nonprofit.location.state }})

Mission
{{ nonprofit.mission }}

Request
{{ grant.amount_line }} Deadline: {{ grant.deadline_line }}

Alignment
{{ templates.alignment_statement }}

Track record
{{ templates.organizational_history }}
""",
    "alignment_statement": """\
Alignment Statement — {{ nonprofit.name }} to {{ grant.title }}

{{ templates.alignment_statement }}

Funder: {{ grant.agency }}
Opportunity: {{ grant.url }}
""",
}


def list_template_kinds() -> tuple[str, ...]:
    return DRAFT_KINDS


def resolve_template(kind: str, soul_templates: dict[str, str] | None = None) -> str:
    """Soul-provided template wins; otherwise the built-in default."""
    if soul_templates and (custom := soul_templates.get(kind)):
        if str(custom).strip():
            return str(custom)
    if kind in DEFAULT_TEMPLATES:
        return DEFAULT_TEMPLATES[kind]
    raise KeyError(f"unknown draft kind {kind!r}; expected one of {', '.join(DRAFT_KINDS)}")


def find_unresolved_variables(kind: str, soul_templates: dict[str, str] | None = None) -> set[str]:
    """Static check of which variables a template references."""
    env = _env()
    try:
        ast = env.parse(resolve_template(kind, soul_templates))
    except TemplateSyntaxError:
        return set()
    return jinja_meta.find_undeclared_variables(ast)


def render(
    kind: str,
    context: dict[str, Any],
    *,
    soul_templates: dict[str, str] | None = None,
) -> RenderResult:
    """Render one draft. Collects every missing variable instead of failing."""
    source = resolve_template(kind, soul_templates)
    env = _env()

    missing: set[str] = set()

    class Tracing(RecordingUndefined):
        """Records the name of each variable that was absent."""

        def __str__(self) -> str:
            missing.add(self._undefined_name or "unknown")
            return MISSING_TEMPLATE.format(name=self._undefined_name or "unknown")

        def __getattr__(self, name: str) -> Any:
            if name.startswith("_"):
                raise AttributeError(name)
            return Tracing(
                hint=self._undefined_hint,
                obj=self._undefined_obj,
                name=f"{self._undefined_name}.{name}",
            )

    env.undefined = Tracing  # type: ignore[assignment]

    try:
        body = env.from_string(source).render(context)
    except TemplateSyntaxError as exc:
        raise ValueError(f"template {kind!r} has a syntax error: {exc}") from exc

    # Tidy the whitespace an empty field can leave behind.
    body = re.sub(r"\n{3,}", "\n\n", body).strip()

    warnings: list[str] = []
    if missing:
        warnings.append(f"{len(missing)} field(s) need human input")

    return RenderResult(
        kind=kind, body=body, missing=sorted(missing), template_used=kind, warnings=warnings
    )


def with_source_footer(body: str, url: str | None) -> str:
    """Append the official-source block. A draft without a link is not shippable."""
    if not url:
        return body + f"\n\n---\nOfficial source: {MISSING_TEMPLATE.format(name='grant.url')}\n"
    return body + "\n\n" + SOURCE_FOOTER.format(url=url)


def referenced_variables(kind: str, soul_templates: dict[str, str] | None = None) -> list[str]:
    return sorted(find_unresolved_variables(kind, soul_templates))


__all__ = [
    "DRAFT_KINDS",
    "DEFAULT_TEMPLATES",
    "MISSING_TEMPLATE",
    "SOURCE_FOOTER",
    "RenderResult",
    "RecordingUndefined",
    "list_template_kinds",
    "resolve_template",
    "render",
    "with_source_footer",
    "referenced_variables",
]