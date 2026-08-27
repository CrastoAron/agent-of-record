"""Demonstrate Stage 5 registry publication, revocation, and verifier integration."""

from __future__ import annotations

import base64
import asyncio
import json
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import httpx

from crypto_core import hash_payload
from key_registry import KeyRegistry
from verifier_service.main import create_app


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _p256_jwk(private_key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _base64url(numbers.x.to_bytes(32, "big")),
        "y": _base64url(numbers.y.to_bytes(32, "big")),
    }


def _stage3_style_envelope(private_key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    payload = {
        "prompt": "send an email to bob@example.com",
        "user_id": "u123",
        "session_id": "registry-demo",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "nonce": "registry-demo-nonce",
    }
    der_signature = private_key.sign(hash_payload(payload), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    return {
        **payload,
        "signature": base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode(),
        "pubkey_id": "email-agent-key",
        "signature_algorithm": "ECDSA-P256-SHA256",
    }


async def run_demo() -> None:
    registry = KeyRegistry()
    app = create_app(key_registry=registry)
    active_private_key = ec.generate_private_key(ec.SECP256R1())
    expired_ed25519 = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    now = datetime.now(timezone.utc)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://demo"
    ) as client:
        print("Register active email-agent key:", (await client.post("/register-key", json={
            "agent_id": "email-agent",
            "pubkey_id": "email-agent-key",
            "algorithm": "ECDSA-P256-SHA256",
            "public_key_jwk": _p256_jwk(active_private_key),
            "valid_from": now.isoformat(),
        })).json())
        print("Register expired archive-agent key:", (await client.post("/register-key", json={
            "agent_id": "archive-agent",
            "pubkey_id": "archive-agent-key",
            "algorithm": "Ed25519",
            "public_key_jwk": {
                "kty": "OKP", "crv": "Ed25519", "x": _base64url(expired_ed25519),
            },
            "valid_from": (now - timedelta(minutes=10)).isoformat(),
            "valid_until": (now - timedelta(minutes=5)).isoformat(),
        })).json())

        print("Initial JWKS:", json.dumps((await client.get("/.well-known/jwks.json")).json(), indent=2))
        print("Stage 3-style envelope:", (await client.post(
            "/api/prompt", json=_stage3_style_envelope(active_private_key)
        )).json())
        print("Revoke active key:", (await client.post(
            "/revoke-key", json={"pubkey_id": "email-agent-key"}
        )).json())
        print("Lookup after revocation:", registry.get_pubkey("email-agent-key"))
        print("JWKS after revocation:", json.dumps((await client.get("/.well-known/jwks.json")).json(), indent=2))


def main() -> None:
    asyncio.run(run_demo())


if __name__ == "__main__":
    main()
