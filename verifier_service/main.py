"""HTTP boundary for the Stage 4 AoR signature verifier."""

from __future__ import annotations

import base64
import binascii
import logging
from collections.abc import Callable
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, SECP256R1
from fastapi import FastAPI, HTTPException, Request, status

from .models import PubkeyRegistration, SignedEnvelope
from .nonce_store import NonceStore
from .pubkey_store import PubkeyStore
from .verifier import SignatureVerifier

logger = logging.getLogger(__name__)


def _base64url_to_bytes(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _p256_jwk_to_der(jwk: dict[str, Any]) -> bytes:
    """Convert the Stage 3 public P-256 JWK to DER for the temporary store."""
    try:
        if jwk["kty"] != "EC" or jwk["crv"] != "P-256":
            raise ValueError("only P-256 EC JWKs are supported")
        public_key = EllipticCurvePublicNumbers(
            int.from_bytes(_base64url_to_bytes(jwk["x"]), "big"),
            int.from_bytes(_base64url_to_bytes(jwk["y"]), "big"),
            SECP256R1(),
        ).public_key()
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise ValueError("invalid P-256 public JWK") from exc
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _registration_key_bytes(registration: PubkeyRegistration) -> bytes:
    if registration.public_key_jwk is not None:
        return _p256_jwk_to_der(registration.public_key_jwk)
    try:
        return base64.b64decode(registration.public_key_b64 or "", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("public_key_b64 must be valid base64 DER") from exc


def _default_verified_handler(_: SignedEnvelope) -> dict[str, str]:
    """Placeholder boundary: no LLM/tool call exists in Stage 4."""
    return {"next": "would proceed to PoI Generator in Stage 6"}


def create_app(
    pubkey_store: PubkeyStore | None = None,
    nonce_store: NonceStore | None = None,
    on_verified: Callable[[SignedEnvelope], dict[str, str]] | None = None,
) -> FastAPI:
    """Build an app with injectable stores/handler for isolated tests."""
    service = FastAPI(title="AoR Signature Verifier", version="0.1.0")
    service.state.pubkey_store = pubkey_store or PubkeyStore()
    service.state.nonce_store = nonce_store or NonceStore()
    service.state.verifier = SignatureVerifier(service.state.pubkey_store, service.state.nonce_store)
    service.state.on_verified = on_verified or _default_verified_handler

    @service.post("/register-pubkey", status_code=status.HTTP_201_CREATED)
    def register_pubkey(registration: PubkeyRegistration, request: Request) -> dict[str, str]:
        try:
            request.app.state.pubkey_store.register_pubkey(
                registration.pubkey_id,
                _registration_key_bytes(registration),
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
        return {"status": "registered", "pubkey_id": registration.pubkey_id}

    @service.post("/api/prompt")
    def verify_prompt(envelope: SignedEnvelope, request: Request) -> dict[str, str]:
        result = request.app.state.verifier.verify_envelope(envelope)
        if not result.valid:
            # Keep useful forensic detail in server logs only. The API response
            # is deliberately generic so it is not a verification oracle.
            logger.warning("AoR verification rejected: reason=%s", result.reason)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="verification_failed",
            )
        return {"status": "verified", **request.app.state.on_verified(envelope)}

    return service


app = create_app()
