"""Inner Court loader + crypto tests. No network, no database."""

from __future__ import annotations

import base64

import pytest

from inner_court import crypto
from inner_court.loader import (
    SoulInvalid,
    SoulNotFound,
    load_soul,
    parse_soul,
    resolve_soul_path,
    soul_is_gitignored,
)
from inner_court.states import NATIONAL, STATES_50, InvalidStateCode, validate_state

VALID_SOUL = """
location:
  city: "Anytown"
  state: "WI"
  zip: "53202"
  country: "US"
matching_rules:
  states: ["WI", "national"]
  exclusions: ["for-profit"]
  min_amount: 5000
nonprofit:
  name: "Anytown Coalition"
  ein: "12-3456789"
  mission: "We serve families."
  populations_served: ["youth"]
templates:
  need_statement: "A real need statement."
secrets:
  api_key: "super-secret-value"
"""


class TestCrypto:
    def test_generate_key_is_32_bytes(self):
        key = crypto.load_master_key(crypto.generate_key())
        assert len(key) == 32

    def test_roundtrip(self):
        key = crypto.load_master_key(crypto.generate_key())
        blob = crypto.encrypt("hello vault", key)
        assert crypto.decrypt(blob, key) == b"hello vault"

    def test_ciphertext_differs_each_time(self):
        """A fresh data key and nonce per call means no ciphertext reuse."""
        key = crypto.load_master_key(crypto.generate_key())
        a, b = crypto.encrypt("same", key), crypto.encrypt("same", key)
        assert a.ciphertext != b.ciphertext
        assert a.wrapped_dek != b.wrapped_dek

    def test_serialize_roundtrip(self):
        key = crypto.load_master_key(crypto.generate_key())
        token = crypto.encrypt("payload", key).serialize()
        assert crypto.decrypt(token, key) == b"payload"

    def test_wrong_key_fails_loudly(self):
        key = crypto.load_master_key(crypto.generate_key())
        other = crypto.load_master_key(crypto.generate_key())
        blob = crypto.encrypt("secret", key)
        with pytest.raises(crypto.DecryptionError):
            crypto.decrypt(blob, other)

    def test_tampered_ciphertext_fails_loudly(self):
        key = crypto.load_master_key(crypto.generate_key())
        blob = crypto.encrypt("secret", key)
        raw = bytearray(base64.b64decode(blob.ciphertext))
        raw[0] ^= 0xFF
        tampered = crypto.EncryptedBlob(
            wrapped_dek=blob.wrapped_dek, nonce=blob.nonce, ciphertext=base64.b64encode(raw).decode()
        )
        with pytest.raises(crypto.DecryptionError):
            crypto.decrypt(tampered, key)

    def test_missing_key_raises_with_guidance(self):
        with pytest.raises(crypto.MissingKeyError) as exc:
            crypto.load_master_key("")
        assert "INNER_COURT_KEY" in str(exc.value)

    def test_bad_length_key_rejected(self):
        with pytest.raises(crypto.VaultError):
            crypto.load_master_key("tooshort")

    def test_blob_repr_leaks_no_plaintext(self):
        key = crypto.load_master_key(crypto.generate_key())
        blob = crypto.encrypt("TOPSECRET", key)
        for rendered in (repr(blob), str(blob)):
            assert "TOPSECRET" not in rendered
            assert blob.ciphertext not in rendered

    def test_redact_hides_value(self):
        assert "abc123" not in crypto.redact("abc123")

    def test_scrub_mapping_recurses_and_hides_secrets(self):
        scrubbed = crypto.scrub_mapping(
            {"outer": {"api_key": "sk-live-123", "name": "visible"}, "token": "t0k"}
        )
        assert scrubbed["outer"]["name"] == "visible"
        assert "sk-live-123" not in str(scrubbed)
        assert "t0k" not in str(scrubbed)

    def test_looks_secret(self):
        assert crypto.looks_secret("GRANTS_GOV_API_KEY")
        assert crypto.looks_secret("client-secret")
        assert not crypto.looks_secret("max_pages")


class TestStateValidation:
    def test_all_50_states_accepted(self):
        assert len(STATES_50) == 50
        for code in STATES_50:
            assert validate_state(code) == code

    def test_lowercase_normalised(self):
        assert validate_state("wi") == "WI"

    def test_territories_rejected_as_home_state(self):
        for code in ("DC", "PR", "GU", "VI", "AS", "MP", "UM"):
            with pytest.raises(InvalidStateCode):
                validate_state(code)

    def test_national_only_allowed_when_requested(self):
        assert validate_state("national", allow_national=True) == NATIONAL
        with pytest.raises(InvalidStateCode):
            validate_state("national")

    def test_bad_code_raises_not_defaults(self):
        """A malformed location must fail, never silently fall back."""
        for bad in ("XX", "", None, "Wisconsin"):
            with pytest.raises(InvalidStateCode):
                validate_state(bad)


class TestLoader:
    def test_parse_valid(self):
        soul = parse_soul(VALID_SOUL)
        assert soul.nonprofit.state == "WI"
        assert soul.nonprofit.city == "Anytown"
        assert soul.matching_rules.states == ("WI", "national")
        assert soul.matching_rules.min_amount == 5000.0
        assert soul.templates["need_statement"] == "A real need statement."

    def test_raw_string_state_rejected(self):
        with pytest.raises(SoulInvalid) as exc:
            parse_soul("location:\n  state: 'Wisconsin'\n")
        assert "not a valid US state code" in str(exc.value)

    def test_unknown_state_rejected(self):
        with pytest.raises(SoulInvalid):
            parse_soul("location:\n  state: 'ZZ'\n")

    def test_invalid_yaml(self):
        with pytest.raises(SoulInvalid):
            parse_soul("location: [unclosed\n")

    def test_empty_file(self):
        with pytest.raises(SoulInvalid):
            parse_soul("")

    def test_non_mapping(self):
        with pytest.raises(SoulInvalid):
            parse_soul("- just\n- a list\n")

    def test_bad_rule_state_rejected(self):
        with pytest.raises(SoulInvalid):
            parse_soul(
                "location:\n  state: WI\nmatching_rules:\n  states: ['WI', 'ZZ']\n"
            )

    def test_rules_default_to_home_state_and_national(self):
        soul = parse_soul("location:\n  state: WI\n")
        assert set(soul.matching_rules.states) == {"WI", "national"}

    def test_repr_hides_secrets_and_raw(self):
        soul = parse_soul(VALID_SOUL)
        rendered = repr(soul)
        assert "super-secret-value" not in rendered
        assert "Anytown Coalition" in rendered

    def test_secrets_are_parsed_but_not_in_template_context(self):
        soul = parse_soul(VALID_SOUL)
        assert soul.secrets["api_key"] == "super-secret-value"
        assert "super-secret-value" not in str(soul.as_template_context())

    def test_load_from_disk(self, tmp_path, monkeypatch):
        path = tmp_path / "soul.md"
        path.write_text(VALID_SOUL)
        monkeypatch.setenv("INNER_COURT_PATH", str(path))
        soul = load_soul()
        assert soul is not None
        assert soul.nonprofit.state == "WI"

    def test_load_missing_raises(self, tmp_path, monkeypatch):
        monkeypatch.setenv("INNER_COURT_PATH", str(tmp_path / "absent.md"))
        with pytest.raises(SoulNotFound):
            load_soul()

    def test_load_missing_optional_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setenv("INNER_COURT_PATH", str(tmp_path / "absent.md"))
        assert load_soul(required=False) is None

    def test_resolve_prefers_explicit(self, tmp_path, monkeypatch):
        monkeypatch.setenv("INNER_COURT_PATH", "/tmp/env.md")
        assert resolve_soul_path(tmp_path / "x.md") == tmp_path / "x.md"

    def test_load_logs_do_not_contain_secret(self, tmp_path, monkeypatch, caplog):
        path = tmp_path / "soul.md"
        path.write_text(VALID_SOUL)
        monkeypatch.setenv("INNER_COURT_PATH", str(path))
        with caplog.at_level("INFO", logger="inner_court.loader"):
            load_soul()
        assert "super-secret-value" not in caplog.text

    def test_example_file_is_valid(self):
        """soul.md.example must load cleanly, or the new-user path is broken."""
        from pathlib import Path

        example = Path(__file__).resolve().parent.parent / "soul.md.example"
        soul = parse_soul(example.read_text())
        assert soul.nonprofit.state in STATES_50
        assert soul.nonprofit.state == "CA"

    def test_soul_is_gitignored(self):
        from pathlib import Path

        repo = Path(__file__).resolve().parent.parent
        assert soul_is_gitignored(repo), "soul.md must be gitignored before users create one"