"""Envelope encryption for the Inner Court vault.

Design: one long-lived *master key* (from ``INNER_COURT_KEY``) wraps a per-vault
*data key*, which in turn encrypts the soul file. Wrapping means rotating the
master key never re-encrypts the data, and revoking one vault is a single record.

Algorithm is AES-256-GCM (FIPS 197): authenticated, so a tampered ciphertext
fails loudly instead of decrypting to garbage. The nonce is random per
encryption and stored alongside the ciphertext - never reused, as GCM requires.

One self-describing token carries everything:

    v1.<wrapped_dek_b64>.<nonce_b64>.<ciphertext_b64>

Plaintext secrets never appear in a log line: callers pass values through
:func:`redact`, and the dataclasses deliberately omit secrets from ``__repr__``.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TOKEN_VERSION = "v1"
_KEY_BYTES = 32  # AES-256
_NONCE_BYTES = 12  # 96-bit, the GCM-recommended size

# Substrings that mark a config key as sensitive.
SECRET_MARKERS = (
    "api_key",
    "apikey",
    "token",
    "secret",
    "password",
    "passwd",
    "private_key",
    "access_key",
    "client_secret",
    "authorization",
    "bearer",
    "session",
    "cookie",
)

_REDACTED = "***redacted***"


class VaultError(RuntimeError):
    """Raised for any vault key or ciphertext problem."""


class MissingKeyError(VaultError):
    """No master key configured."""


class DecryptionError(VaultError):
    """Ciphertext failed authentication - wrong key or tampering."""


def generate_key() -> str:
    """A fresh base64 256-bit key, suitable for ``INNER_COURT_KEY``."""
    return base64.urlsafe_b64encode(os.urandom(_KEY_BYTES)).decode("ascii")


def load_master_key(raw: str | bytes | None) -> bytes:
    """Decode a base64 (or raw 32 byte) master key, with actionable errors."""
    if raw is None or raw == "":
        raise MissingKeyError(
            "INNER_COURT_KEY is not set. Generate one with "
            "`python -m inner_court.crypto --generate` and export it."
        )
    if isinstance(raw, bytes):
        raw = raw.decode("ascii", "strict")

    candidate = raw.strip()
    try:
        key = base64.urlsafe_b64decode(candidate + "=" * (-len(candidate) % 4))
    except Exception:
        key = candidate.encode("utf-8", "ignore")

    if len(key) != _KEY_BYTES:
        raise VaultError(
            f"master key must decode to {_KEY_BYTES} bytes for AES-256, got {len(key)}. "
            "Generate one with `python -m inner_court.crypto --generate`."
        )
    return key


@dataclass(frozen=True)
class EncryptedBlob:
    """A wrapped data key plus a ciphertext. Safe to repr/log (no plaintext)."""

    wrapped_dek: str
    nonce: str
    ciphertext: str
    version: str = TOKEN_VERSION

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<EncryptedBlob {self.version} ciphertext={len(self.ciphertext)}b>"

    def serialize(self) -> str:
        return ".".join((self.version, self.wrapped_dek, self.nonce, self.ciphertext))

    @classmethod
    def parse(cls, token: str) -> EncryptedBlob:
        parts = token.strip().split(".")
        if len(parts) != 4 or parts[0] != TOKEN_VERSION:
            raise VaultError("unrecognised vault token; expected v1.<dek>.<nonce>.<ct>")
        return cls(wrapped_dek=parts[1], nonce=parts[2], ciphertext=parts[3])


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(raw: str) -> bytes:
    try:
        return base64.b64decode(raw, validate=True)
    except Exception as exc:  # pragma: no cover - malformed input
        raise VaultError("vault token is not valid base64") from exc


def encrypt(plaintext: str | bytes, master_key: bytes) -> EncryptedBlob:
    """Encrypt with a fresh data key, wrapped under ``master_key``."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(_NONCE_BYTES)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, None)

    # The wrapping nonce is prepended to the wrapped key so decrypt can split it.
    wrap_nonce = os.urandom(_NONCE_BYTES)
    wrapped_dek = wrap_nonce + AESGCM(master_key).encrypt(wrap_nonce, dek, None)

    return EncryptedBlob(wrapped_dek=_b64(wrapped_dek), nonce=_b64(nonce), ciphertext=_b64(ciphertext))


def decrypt(blob: EncryptedBlob | str, master_key: bytes) -> bytes:
    """Recover the plaintext, raising :class:`DecryptionError` on tampering."""
    if isinstance(blob, str):
        blob = EncryptedBlob.parse(blob)

    wrapped = _unb64(blob.wrapped_dek)
    try:
        dek = AESGCM(master_key).decrypt(wrapped[:_NONCE_BYTES], wrapped[_NONCE_BYTES:], None)
    except InvalidTag as exc:
        raise DecryptionError("could not unwrap the data key: wrong INNER_COURT_KEY") from exc

    try:
        return AESGCM(dek).decrypt(_unb64(blob.nonce), _unb64(blob.ciphertext), None)
    except InvalidTag as exc:
        raise DecryptionError("vault contents failed authentication: file was modified") from exc


def redact(value: Any, *, keep: int = 0) -> str:
    """Render a value safe for logs: secrets collapse to a fixed marker."""
    if value is None:
        return ""
    text = str(value)
    if not text:
        return ""
    if keep and len(text) > keep:
        return f"{text[:keep]}…{_REDACTED}"
    return _REDACTED


def looks_secret(key: str) -> bool:
    """True when a config key name implies its value is sensitive."""
    lowered = key.strip().lower().replace("-", "_")
    return any(marker in lowered for marker in SECRET_MARKERS)


def scrub_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively replace secret-looking values, for safe logging/telemetry."""
    out: dict[str, Any] = {}
    for key, value in data.items():
        if looks_secret(str(key)):
            out[key] = redact(value)
        elif isinstance(value, dict):
            out[key] = scrub_mapping(value)
        elif isinstance(value, list):
            out[key] = [scrub_mapping(v) if isinstance(v, dict) else v for v in value]
        else:
            out[key] = value
    return out


def _main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Inner Court vault key utility")
    parser.add_argument("--generate", action="store_true", help="print a new INNER_COURT_KEY")
    args = parser.parse_args(argv)

    if args.generate:
        print(generate_key())
        return 0
    parser.print_help()
    return 1


if __name__ == "__main__":  # pragma: no cover - CLI
    raise SystemExit(_main())


__all__ = [
    "SECRET_MARKERS",
    "DecryptionError",
    "EncryptedBlob",
    "MissingKeyError",
    "VaultError",
    "decrypt",
    "encrypt",
    "generate_key",
    "load_master_key",
    "looks_secret",
    "redact",
    "scrub_mapping",
]