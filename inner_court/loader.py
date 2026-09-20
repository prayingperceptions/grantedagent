"""Load and validate the Inner Court soul file.

The soul file is the nonprofit's private brain: who they are, where they are,
and what they will and won't accept. It is plain YAML so a human can read and
edit it without tooling.

Two rules drive the implementation:

1. **Never log secrets.** The file may carry an LLM API key. Anything that
   formats a Soul passes through :func:`inner_court.crypto.scrub_mapping`, and
   ``Soul.__repr__`` exposes only non-sensitive shape.
2. **Fail loudly on malformed input.** A bad state code is an error, not a
   default. Silently falling back to "national" would misdirect every match.

The file path comes from ``INNER_COURT_PATH`` (default ``./soul.md``).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from hunter.config import get_settings
from inner_court.crypto import scrub_mapping
from inner_court.states import NATIONAL, InvalidStateCode, validate_state

logger = logging.getLogger("inner_court.loader")

DEFAULT_SOUL_FILENAME = "soul.md"
DEFAULT_RELATIVE_PATH = Path("granted-agent") / DEFAULT_SOUL_FILENAME


class SoulError(RuntimeError):
    """Base class for soul file problems."""


class SoulNotFound(SoulError):
    """No soul file at the configured path."""


class SoulInvalid(SoulError):
    """The soul file exists but cannot be used."""


@dataclass(frozen=True)
class Nonprofit:
    name: str = ""
    ein: str = ""
    mission: str = ""
    city: str = ""
    state: str = ""
    zip: str = ""
    country: str = "US"
    populations_served: tuple[str, ...] = ()
    focus_areas: tuple[str, ...] = ()
    past_grants: tuple[str, ...] = ()

    @property
    def location_line(self) -> str:
        parts = [p for p in (self.city, self.state) if p]
        return ", ".join(parts)


@dataclass(frozen=True)
class MatchingRules:
    """Hard filters. Exclusions win: an excluded grant scores -1.0."""

    states: tuple[str, ...] = ()
    exclusions: tuple[str, ...] = ()
    min_amount: float | None = None
    focus_areas: tuple[str, ...] = ()

    def allows_national(self) -> bool:
        return NATIONAL in self.states

    def covers_state(self, code: str | None) -> bool:
        code = (code or "").strip().upper()
        return bool(code) and code in self.states


@dataclass(frozen=True)
class Soul:
    """A validated soul file. Secrets are held but never rendered."""

    nonprofit: Nonprofit
    matching_rules: MatchingRules
    templates: dict[str, str] = field(default_factory=dict)
    grants: dict[str, Any] = field(default_factory=dict)
    booleans: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    source_path: Path | None = None
    secrets: dict[str, str] = field(default_factory=dict, repr=False)
    encrypted: bool = False

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        # Deliberately excludes `raw` and `secrets`: both may hold a key.
        return (
            f"<Soul {self.nonprofit.name or 'unnamed'} "
            f"state={self.nonprofit.state} rules={list(self.matching_rules.states)} "
            f"encrypted={self.encrypted}>"
        )

    def template(self, name: str) -> str:
        return self.templates.get(name, "")

    def as_template_context(self) -> dict[str, Any]:
        """Everything Jinja may reference as ``{{ nonprofit.* }}`` / ``{{ grant.* }}``."""
        return {
            "nonprofit": {
                "name": self.nonprofit.name,
                "ein": self.nonprofit.ein,
                "mission": self.nonprofit.mission,
                "location": {
                    "city": self.nonprofit.city,
                    "state": self.nonprofit.state,
                    "zip": self.nonprofit.zip,
                    "country": self.nonprofit.country,
                },
                "populations_served": list(self.nonprofit.populations_served),
                "focus_areas": list(self.nonprofit.focus_areas),
                "past_grants": list(self.nonprofit.past_grants),
            },
            "matching_rules": {
                "states": list(self.matching_rules.states),
                "exclusions": list(self.matching_rules.exclusions),
            },
            "templates": dict(self.templates),
        }


def resolve_soul_path(explicit: str | os.PathLike[str] | None = None) -> Path:
    """Resolve the soul path: explicit arg, then INNER_COURT_PATH, then ./soul.md.

    Read via settings so a ``.env`` file works the same as an exported variable,
    falling back to the environment for the bare-bones case.

    Fails loudly rather than defaulting when a path is configured but missing:
    a silent fallback would score every grant against the wrong nonprofit.
    """
    if explicit is not None:
        return Path(explicit).expanduser()
    configured = get_settings().inner_court_path or os.environ.get("INNER_COURT_PATH")
    if configured:
        return Path(configured).expanduser()
    return Path.cwd() / DEFAULT_RELATIVE_PATH


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value.strip(),) if value.strip() else ()
    if isinstance(value, (list, tuple, set)):
        return tuple(str(v).strip() for v in value if str(v).strip())
    return (str(value).strip(),)


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(str(value).replace(",", "").replace("$", "").strip())
    except (TypeError, ValueError):
        return None


def parse_soul(text: str, *, source_path: Path | None = None) -> Soul:
    """Parse and validate soul YAML. Raises :class:`SoulInvalid` on bad input."""
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SoulInvalid(f"soul file is not valid YAML: {exc}") from exc

    if loaded is None:
        raise SoulInvalid("soul file is empty")
    if not isinstance(loaded, dict):
        raise SoulInvalid("soul file must be a YAML mapping at the top level")

    location = loaded.get("location") or {}
    if not isinstance(location, dict):
        raise SoulInvalid("`location` must be a mapping with city/state/zip")
    identity = loaded.get("nonprofit") or {}
    if not isinstance(identity, dict):
        raise SoulInvalid("`nonprofit` must be a mapping")

    # A malformed state must fail loudly - see module docstring.
    raw_state = location.get("state")
    try:
        state = validate_state(raw_state, field="location.state")
    except InvalidStateCode as exc:
        raise SoulInvalid(str(exc)) from exc

    nonprofit = Nonprofit(
        name=str(identity.get("name") or loaded.get("name") or "").strip(),
        ein=str(identity.get("ein") or "").strip(),
        mission=str(identity.get("mission") or "").strip(),
        city=str(location.get("city") or "").strip(),
        state=state,
        zip=str(location.get("zip") or "").strip(),
        country=str(location.get("country") or "US").strip().upper(),
        populations_served=_as_tuple(identity.get("populations_served")),
        focus_areas=_as_tuple(identity.get("focus_areas")),
        past_grants=_as_tuple(identity.get("past_grants")),
    )

    rules_raw = loaded.get("matching_rules") or {}
    if not isinstance(rules_raw, dict):
        raise SoulInvalid("`matching_rules` must be a mapping")

    states: list[str] = []
    for entry in _as_tuple(rules_raw.get("states")):
        try:
            states.append(validate_state(entry, allow_national=True, field="matching_rules.states"))
        except InvalidStateCode as exc:
            raise SoulInvalid(str(exc)) from exc

    # Default to the nonprofit's own state plus national when unspecified, so a
    # minimal soul file still produces sensible matching.
    if not states:
        states = [nonprofit.state, NATIONAL]

    rules = MatchingRules(
        states=tuple(dict.fromkeys(states)),
        exclusions=_as_tuple(rules_raw.get("exclusions")),
        min_amount=_as_float(rules_raw.get("min_amount")),
        focus_areas=_as_tuple(rules_raw.get("focus_areas")),
    )

    templates_raw = loaded.get("templates") or {}
    templates = {str(k): str(v) for k, v in templates_raw.items()} if isinstance(templates_raw, dict) else {}

    grants_raw = loaded.get("grants") or {}
    secrets_raw = loaded.get("secrets") or {}

    return Soul(
        nonprofit=nonprofit,
        matching_rules=rules,
        templates=templates,
        grants=grants_raw if isinstance(grants_raw, dict) else {},
        booleans=loaded,
        raw=loaded,
        source_path=source_path,
        secrets={str(k): str(v) for k, v in secrets_raw.items()} if isinstance(secrets_raw, dict) else {},
    )


def load_soul(
    path: str | os.PathLike[str] | None = None,
    *,
    required: bool = True,
) -> Soul | None:
    """Load the soul file from ``INNER_COURT_PATH`` (or ``path``).

    Logs only the resolved path and the non-sensitive shape of the result.
    """
    resolved = resolve_soul_path(path)

    if not resolved.exists():
        if required:
            raise SoulNotFound(
                f"no soul file at {resolved}. Copy soul.md.example to {DEFAULT_RELATIVE_PATH} "
                "or set INNER_COURT_PATH."
            )
        logger.info("inner_court: no soul file at %s (optional load)", resolved)
        return None

    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise SoulNotFound(f"could not read soul file at {resolved}: {exc}") from exc

    soul = parse_soul(text, source_path=resolved)

    # Log shape only. scrub_mapping guards against a secret in a nested key.
    logger.info(
        "inner_court: loaded soul %s",
        scrub_mapping(
            {
                "path": str(resolved),
                "nonprofit": soul.nonprofit.name,
                "state": soul.nonprofit.state,
                "rules": list(soul.matching_rules.states),
                "templates": sorted(soul.templates),
                "api_key": soul.secrets.get("api_key"),
            }
        ),
    )
    return soul


def soul_is_gitignored(repo_root: str | os.PathLike[str] | None = None) -> bool:
    """True when the default soul filename is covered by .gitignore."""
    root = Path(repo_root or Path.cwd())
    gitignore = root / ".gitignore"
    if not gitignore.exists():
        return False
    patterns = {
        line.strip()
        for line in gitignore.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    return any(
        pattern in patterns
        for pattern in (
            DEFAULT_SOUL_FILENAME,
            f"**/{DEFAULT_SOUL_FILENAME}",
            f"*{DEFAULT_SOUL_FILENAME}",
            f"{DEFAULT_RELATIVE_PATH}",
        )
    )


__all__ = [
    "DEFAULT_SOUL_FILENAME",
    "MatchingRules",
    "Nonprofit",
    "Soul",
    "SoulError",
    "SoulInvalid",
    "SoulNotFound",
    "load_soul",
    "parse_soul",
    "resolve_soul_path",
    "soul_is_gitignored",
]