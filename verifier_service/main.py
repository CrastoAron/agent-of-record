"""HTTP boundary for the Stage 4 AoR signature verifier."""

from __future__ import annotations

import base64
import binascii
import logging
from collections.abc import Callable
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request, status

from key_registry import KeyRegistry
from key_registry.jwks import import_jwk
from key_registry.models import RegisterKeyRequest, RevokeKeyRequest

from .models import PubkeyRegistration, SignedEnvelope
from .nonce_store import NonceStore
from .pubkey_store import PubkeyStore
from .verifier import SignatureVerifier

logger = logging.getLogger(__name__)


def _registration_key_bytes(registration: PubkeyRegistration) -> bytes:
    if registration.public_key_jwk is not None:
        return import_jwk(registration.public_key_jwk)
    try:
        return base64.b64decode(registration.public_key_b64 or "", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("public_key_b64 must be valid base64 DER") from exc


def _registry_registration_key_bytes(registration: RegisterKeyRequest) -> bytes:
    if registration.public_key_jwk is not None:
        return import_jwk(registration.public_key_jwk)
    try:
        return base64.b64decode(registration.public_key_b64 or "", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("public_key_b64 must be valid base64 key material") from exc


def _default_verified_handler(_: SignedEnvelope) -> dict[str, str]:
    """Placeholder boundary: no LLM/tool call exists in Stage 4."""
    return {"next": "would proceed to PoI Generator in Stage 6"}


def create_app(
    pubkey_store: PubkeyStore | KeyRegistry | None = None,
    nonce_store: NonceStore | None = None,
    on_verified: Callable[[SignedEnvelope], dict[str, str]] | None = None,
    key_registry: KeyRegistry | None = None,
) -> FastAPI:
    """Build an app with injectable stores/handler for isolated tests."""
    service = FastAPI(title="AoR Signature Verifier", version="0.1.0")
    # The default is now the Stage 5 registry. A legacy PubkeyStore remains
    # injectable for focused Stage 4 tests through the same get_pubkey API.
    service.state.pubkey_store = key_registry or pubkey_store or KeyRegistry()
    service.state.key_registry = (
        service.state.pubkey_store if isinstance(service.state.pubkey_store, KeyRegistry) else None
    )
    service.state.nonce_store = nonce_store or NonceStore()
    service.state.verifier = SignatureVerifier(service.state.pubkey_store, service.state.nonce_store)
    service.state.on_verified = on_verified or _default_verified_handler

    @service.post("/register-pubkey", status_code=status.HTTP_201_CREATED)
    async def register_pubkey(registration: PubkeyRegistration, request: Request) -> dict[str, str]:
        try:
            request.app.state.pubkey_store.register_pubkey(
                registration.pubkey_id,
                _registration_key_bytes(registration),
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
        return {"status": "registered", "pubkey_id": registration.pubkey_id}

    @service.post("/register-key", status_code=status.HTTP_201_CREATED)
    async def register_key(registration: RegisterKeyRequest, request: Request) -> dict[str, str]:
        registry = request.app.state.key_registry
        if registry is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="key_registry_not_configured",
            )
        try:
            record = registry.register_key(
                agent_id=registration.agent_id,
                pubkey_id=registration.pubkey_id,
                public_key_bytes=_registry_registration_key_bytes(registration),
                algorithm=registration.algorithm,
                valid_from=registration.valid_from or datetime.now(timezone.utc),
                valid_until=registration.valid_until,
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
        return {"status": "registered", "agent_id": record.agent_id, "pubkey_id": record.pubkey_id}

    @service.get("/.well-known/jwks.json")
    async def get_jwks(request: Request) -> dict[str, list[dict[str, str]]]:
        registry = request.app.state.key_registry
        if registry is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="key_registry_not_configured",
            )
        return registry.export_jwks()

    @service.post("/revoke-key")
    async def revoke_key(revocation: RevokeKeyRequest, request: Request) -> dict[str, str]:
        registry = request.app.state.key_registry
        if registry is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="key_registry_not_configured",
            )
        if not registry.revoke_key(revocation.pubkey_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="key_not_found")
        return {"status": "revoked", "pubkey_id": revocation.pubkey_id}

    @service.post("/api/prompt")
    async def verify_prompt(envelope: SignedEnvelope, request: Request) -> dict[str, str]:
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
