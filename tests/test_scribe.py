"""Scribe tests: templates, context assembly, and the no-invention contract."""

from __future__ import annotations

from datetime import date
from types import SimpleNamespace

import pytest

from inner_court.loader import parse_soul
from scribe import draft_generator as dg
from scribe import templater

FULL_SOUL = """
location:
  city: "Anytown"
  state: "WI"
  zip: "53202"
nonprofit:
  name: "Anytown Coalition"
  ein: "12-3456789"
  mission: "We serve families across southeastern Wisconsin."
  signatory_name: "Dana Director"
  signatory_title: "Executive Director"
  total_budget: 450000
  populations_served: ["youth", "seniors"]
  focus_areas: ["community health"]
templates:
  need_statement: "Need text."
  budget_narrative: "Budget text."
  organizational_history: "History text."
  alignment_statement: "Alignment text."
"""

GRANT = SimpleNamespace(
    title="Community Health Grant",
    agency="Anytown Foundation",
    url="https://example.org/g/1",
    source="state_WI",
    state_code="WI",
    description="Funds primary care.",
    deadline=date(2026, 11, 30),
    amount_min=10000,
    amount_max=50000,
)


class TestTemplater:
    def test_all_kinds_render(self):
        soul = parse_soul(FULL_SOUL)
        ctx = dg.build_context(soul, GRANT)
        for kind in templater.DRAFT_KINDS:
            result = templater.render(kind, ctx, soul_templates=soul.templates)
            assert result.body.strip(), kind

    def test_missing_variable_is_marked_not_blank(self):
        result = templater.render(
            "loi",
            {"nonprofit": {"name": "X"}, "grant": {"title": "Y"}, "templates": {}},
        )
        assert templater.MISSING_TEMPLATE.format(name="need_statement") in result.body
        assert result.missing

    def test_missing_variables_are_recorded(self):
        result = templater.render("loi", {"nonprofit": {}, "grant": {}, "templates": {}})
        assert "need_statement" in result.missing
        assert "alignment_statement" in result.missing

    def test_soul_template_overrides_default(self):
        soul = parse_soul(FULL_SOUL)
        ctx = dg.build_context(soul, GRANT)
        result = templater.render("need_statement", ctx, soul_templates=soul.templates)
        assert "Need text." in result.body

    def test_unknown_kind_raises(self):
        with pytest.raises(KeyError):
            templater.resolve_template("no_such_kind")

    def test_syntax_error_raises_value_error(self):
        with pytest.raises(ValueError):
            templater.render("loi", {}, soul_templates={"loi": "{% for x in %}"})

    def test_source_footer_always_links(self):
        out = templater.with_source_footer("body", "https://example.org/x")
        assert "https://example.org/x" in out
        assert "Verify" in out

    def test_source_footer_marks_a_missing_url(self):
        out = templater.with_source_footer("body", None)
        assert "NEEDS HUMAN INPUT" in out

    def test_referenced_variables(self):
        names = templater.referenced_variables("loi")
        assert "nonprofit" in names and "grant" in names


class TestContextAssembly:
    def test_no_invention_when_fields_absent(self):
        """A minimal soul must not cause the Scribe to invent a signatory."""
        soul = parse_soul("location:\n  state: WI\nnonprofit:\n  name: 'Minimal'\n")
        ctx = dg.build_context(soul, GRANT)
        assert "signatory_name" not in ctx["nonprofit"]

    def test_blank_boilerplate_is_treated_as_absent(self):
        soul = parse_soul(
            "location:\n  state: WI\nnonprofit:\n  name: 'X'\ntemplates:\n  need_statement: '   '\n"
        )
        ctx = dg.build_context(soul, GRANT)
        assert "need_statement" not in ctx["templates"]

    def test_salutation_falls_back_without_inventing_a_name(self):
        soul = parse_soul(FULL_SOUL)
        ctx = dg.build_context(soul, GRANT)
        assert ctx["grant"]["funder_salutation"] == "Anytown Foundation team"

    def test_amount_and_deadline_lines(self):
        soul = parse_soul(FULL_SOUL)
        ctx = dg.build_context(soul, GRANT)
        assert ctx["grant"]["amount_line"] == "$10,000 – $50,000"
        assert "2026-11-30" in ctx["grant"]["deadline_line"]

    def test_amount_line_with_only_max(self):
        g = SimpleNamespace(**{**GRANT.__dict__, "amount_min": None})
        soul = parse_soul(FULL_SOUL)
        assert dg.build_context(soul, g)["grant"]["amount_line"] == "$50,000"

    def test_zero_amounts_render_empty(self):
        g = SimpleNamespace(**{**GRANT.__dict__, "amount_min": 0, "amount_max": 0})
        soul = parse_soul(FULL_SOUL)
        assert dg.build_context(soul, g)["grant"]["amount_line"] == ""

    def test_state_comes_from_soul_not_hardcoded(self):
        soul = parse_soul(FULL_SOUL.replace('state: "WI"', 'state: "OR"'))
        ctx = dg.build_context(soul, GRANT)
        assert ctx["nonprofit"]["location"]["state"] == "OR"


class TestGenerate:
    def test_generate_returns_requested_kinds(self):
        soul = parse_soul(FULL_SOUL)
        out = dg.generate(soul, GRANT, kinds=("loi", "cover_letter"))
        assert [d.kind for d in out] == ["loi", "cover_letter"]

    def test_bodies_are_deterministic(self):
        soul = parse_soul(FULL_SOUL)
        a = dg.generate(soul, GRANT, kinds=("loi",))[0].body
        b = dg.generate(soul, GRANT, kinds=("loi",))[0].body
        assert a == b

    def test_full_soul_has_no_missing_inputs(self):
        soul = parse_soul(FULL_SOUL)
        out = dg.generate(soul, GRANT, kinds=("loi", "cover_letter"))
        for d in out:
            assert d.missing == [], f"{d.kind} unexpectedly missing {d.missing}"

    def test_minimal_soul_reports_missing_inputs(self):
        soul = parse_soul("location:\n  state: WI\nnonprofit:\n  name: 'Minimal'\n")
        out = dg.generate(soul, GRANT, kinds=("loi",))
        assert "signatory_name" in out[0].missing

    def test_every_draft_links_the_official_source(self):
        soul = parse_soul(FULL_SOUL)
        for d in dg.generate(soul, GRANT, kinds=templater.DRAFT_KINDS):
            assert GRANT.url in d.body

    def test_unknown_kind_raises_draft_error(self):
        soul = parse_soul(FULL_SOUL)
        with pytest.raises(dg.DraftError):
            dg.generate(soul, GRANT, kinds=("bogus",))

    def test_wi_soul_drafts_mention_wisconsin(self):
        soul = parse_soul(FULL_SOUL)
        body = dg.generate(soul, GRANT, kinds=("loi",))[0].body
        assert "WI" in body or "Wisconsin" in body