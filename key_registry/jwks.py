"""JWK Set encoding and decoding for supported AoR public-key algorithms."""

from __future__ import annotations

import base64
import binascii
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, SECP256R1
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .models import AgentKeyRecord


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _load_supported_public_key(public_key_bytes: bytes) -> Ed25519PublicKey | EllipticCurvePublicKey:
    """Load DER SPKI, or raw 32-byte Ed25519 form used by JWK consumers."""
    try:
        public_key = serialization.load_der_public_key(public_key_bytes)
    except ValueError:
        if len(public_key_bytes) == 32:
            return Ed25519PublicKey.from_public_bytes(public_key_bytes)
        raise ValueError("public key must be DER SPKI or raw 32-byte Ed25519")
    if not isinstance(public_key, (Ed25519PublicKey, EllipticCurvePublicKey)):
        raise ValueError("unsupported public key type")
    return public_key


def public_key_to_jwk(record: AgentKeyRecord) -> dict[str, str]:
    """Encode one active record as a standard public JWK."""
    public_key = _load_supported_public_key(record.public_key_bytes)
    common = {"kid": record.pubkey_id, "use": "sig"}
    if isinstance(public_key, Ed25519PublicKey):
        raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {**common, "kty": "OKP", "crv": "Ed25519", "x": _base64url_encode(raw), "alg": "EdDSA"}
    if isinstance(public_key, EllipticCurvePublicKey) and isinstance(public_key.curve, SECP256R1):
        numbers = public_key.public_numbers()
        return {
            **common,
            "kty": "EC",
            "crv": "P-256",
            "x": _base64url_encode(numbers.x.to_bytes(32, "big")),
            "y": _base64url_encode(numbers.y.to_bytes(32, "big")),
            "alg": "ES256",
        }
    raise ValueError("only Ed25519 and ECDSA P-256 public keys are supported")


def export_jwks(records: list[AgentKeyRecord]) -> dict[str, list[dict[str, str]]]:
    """Return the standard JWK Set document for the supplied active records."""
    return {"keys": [public_key_to_jwk(record) for record in records]}


def import_jwk(jwk: dict[str, Any]) -> bytes:
    """Parse an Ed25519 or P-256 JWK into registry public-key bytes.

    Ed25519 returns its interoperable raw 32-byte form. P-256 returns DER
    SubjectPublicKeyInfo bytes, matching the Web Crypto registration path.
    """
    try:
        if jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519":
            raw_key = _base64url_decode(jwk["x"])
            Ed25519PublicKey.from_public_bytes(raw_key)
            return raw_key
        if jwk["kty"] == "EC" and jwk["crv"] == "P-256":
            from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers

            public_key = EllipticCurvePublicNumbers(
                int.from_bytes(_base64url_decode(jwk["x"]), "big"),
                int.from_bytes(_base64url_decode(jwk["y"]), "big"),
                SECP256R1(),
            ).public_key()
            return public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise ValueError("invalid supported public JWK") from exc
    raise ValueError("unsupported JWK type")
