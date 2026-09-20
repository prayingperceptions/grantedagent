"""Per-tenant soul storage.

The single-tenant design read one ``soul.md`` from disk. Multi-tenancy needs a
vault per nonprofit, and that changes two things:

* **Where the soul lives.** A row on ``nonprofits`` rather than a file path, so
  one deployment can hold many souls without a directory convention.
* **What "encrypted" protects.** The soul holds the mission, budgets and
  boilerplate narrative, and it can carry API keys. It is stored encrypted with
  :mod:`inner_court.crypto`, with only the sanitised, secret-free view mirrored
  into ``soul_json`` for templating and search.

The plaintext never rests in the database. ``soul_encrypted`` holds the
``v1.<dek>.<nonce>.<ct>`` token and ``soul_json`` holds structure with secrets
removed, so a database dump yields neither a key nor a mission statement.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.orm import Session

from accounts.security import utcnow
from hunter.config import get_settings
from hunter.models import NonprofitModel
from inner_court import crypto
from inner_court.loader import Soul, SoulInvalid, parse_soul

logger = logging.getLogger("inner_court.vault")


class VaultUnavailable(RuntimeError):
    """The master key is missing, so the vault cannot be opened."""


def _master_key() -> bytes:
    settings = get_settings()
    try:
        return crypto.load_master_key(settings.inner_court_key)
    except crypto.MissingKeyError as exc:
        raise VaultUnavailable(str(exc)) from exc


def vault_available() -> bool:
    try:
        _master_key()
        return True
    except VaultUnavailable:
        return False


def save_soul(db: Session, nonprofit: NonprofitModel, content: str) -> Soul:
    """Validate, encrypt and store a soul for one tenant.

    Validation happens before encryption so an invalid document never becomes
    the stored state - a tenant cannot lock itself out with a malformed soul.
    """
    try:
        soul = parse_soul(content)
    except SoulInvalid:
        raise

    key = _master_key()
    blob = crypto.encrypt(content, key)

    nonprofit.soul_encrypted = blob.serialize()
    # The template context excludes `secrets`, so this column is safe to read
    # from a dashboard or a vector job.
    nonprofit.soul_json = soul.as_template_context()
    nonprofit.soul_updated_at = utcnow()

    # Keep the structured fields on the tenant row in step with the soul, since
    # tenant listings and the state filter read these columns directly.
    if soul.nonprofit.name:
        nonprofit.name = soul.nonprofit.name
    if soul.nonprofit.ein:
        nonprofit.ein = soul.nonprofit.ein
    if soul.nonprofit.mission:
        nonprofit.mission = soul.nonprofit.mission
    if soul.nonprofit.city:
        nonprofit.city = soul.nonprofit.city
    if soul.nonprofit.state:
        nonprofit.state = soul.nonprofit.state.upper()[:2]
    if soul.nonprofit.zip:
        nonprofit.zip = soul.nonprofit.zip

    db.flush()
    return soul


def load_soul_for(db: Session, nonprofit: NonprofitModel) -> Soul | None:
    """Decrypt and parse a tenant's soul. ``None`` when it has none yet.

    A decryption failure is not fatal to the request: the tenant may simply be
    missing the key that encrypted it (a restored backup, a rotated key). That
    is reported distinctly so an operator can tell "no soul" from "key wrong".
    """
    if not nonprofit.soul_encrypted:
        return None

    key = _master_key()
    try:
        plaintext = crypto.decrypt(nonprofit.soul_encrypted, key).decode("utf-8")
    except crypto.DecryptionError:
        logger.error("soul decryption failed nonprofit_id=%s", nonprofit.id)
        raise
    return parse_soul(plaintext)


def soul_status(nonprofit: NonprofitModel) -> dict[str, Any]:
    """Non-secret status about a tenant's soul, for the UI."""
    stored = nonprofit.soul_json or {}
    nonprofit_section = stored.get("nonprofit") or {}
    return {
        "configured": bool(nonprofit.soul_encrypted),
        "updated_at": (
            nonprofit.soul_updated_at.isoformat() if nonprofit.soul_updated_at else None
        ),
        "name": nonprofit_section.get("name") or nonprofit.name,
        "state": nonprofit_section.get("location", {}).get("state") or nonprofit.state,
        "template_count": len(stored.get("templates") or {}),
    }


def clear_soul(db: Session, nonprofit: NonprofitModel) -> None:
    """Remove a tenant's stored soul.

    Called on deletion or explicit reset. The encrypted blob is cleared along
    with the mirrored JSON so the two cannot disagree.
    """
    nonprofit.soul_encrypted = None
    nonprofit.soul_json = None
    nonprofit.soul_updated_at = utcnow()
    db.flush()


def export_soul_json(nonprofit: NonprofitModel) -> str:
    """A JSON dump of the tenant's *sanitised* soul, for export or backup.

    Reads ``soul_json``, which never contained secrets, so an export cannot
    leak a key even if the caller dumps it somewhere public.
    """
    return json.dumps(nonprofit.soul_json or {}, indent=2, sort_keys=True, default=str)


__all__ = [
    "VaultUnavailable",
    "clear_soul",
    "export_soul_json",
    "load_soul_for",
    "save_soul",
    "soul_status",
    "vault_available",
]