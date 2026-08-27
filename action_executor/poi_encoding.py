"""Canonical header encoding shared by SMTP sending and later verification."""

from __future__ import annotations

import base64

from crypto_core import canonicalize
from poi_generator.models import ProofOfIntent


def _urlsafe_base64_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _urlsafe_base64_decode(value: str) -> bytes:
    # Email libraries may fold long headers with whitespace; unfolded values are
    # normally supplied by parsers, but accepting it makes decoding robust.
    compact_value = "".join(value.split())
    return base64.urlsafe_b64decode(compact_value)


def encode_poi_header(poi: ProofOfIntent) -> str:
    """Encode the complete, signed PoI as canonical JSON in base64url form."""
    return _urlsafe_base64_encode(canonicalize(poi.model_dump()))


def decode_poi_header(header_value: str) -> ProofOfIntent:
    """Decode the complete PoI from an X-AoR-Proof-of-Intent header."""
    return ProofOfIntent.model_validate_json(_urlsafe_base64_decode(header_value))


def build_signature_header(poi: ProofOfIntent) -> str:
    """Return the raw agent signature in base64url for quick SMTP inspection.

    This intentionally duplicates the signature inside the full PoI header. The
    standalone header lets a receiver cheaply locate the signature, while the
    complete PoI remains the authoritative, self-contained audit artifact.
    """
    if poi.agent_signature is None:
        raise ValueError("a signed PoI is required for an action header")
    return _urlsafe_base64_encode(bytes.fromhex(poi.agent_signature))


def build_agent_cert_header(agent_pubkey_id: str | None) -> str:
    """Return the Stage 5 public-key/JWK reference for X-AoR-Agent-Cert."""
    if not agent_pubkey_id:
        raise ValueError("agent_pubkey_id is required for an action header")
    return agent_pubkey_id
