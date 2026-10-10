from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timezone

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from crypto_core import hash_payload
from verifier_service.main import create_app


async def _request(app, method: str, path: str, payload: dict[str, object] | None = None):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        return await client.request(method, path, json=payload)


def _signed_envelope(private_key, prompt: str, nonce: str, pubkey_id: str) -> dict[str, str]:
    signing_payload = {
        "prompt": prompt,
        "user_id": "u123",
        "session_id": "frontend-session",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "nonce": nonce,
    }
    der_signature = private_key.sign(hash_payload(signing_payload), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    return {
        **signing_payload,
        "signature": base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode(),
        "pubkey_id": pubkey_id,
    }


def _public_key_b64(private_key) -> str:
    return base64.b64encode(
        private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode()


def test_frontend_style_prompt_routes_to_file_agent(tmp_path):
    app = create_app(
        database_path=tmp_path / "aor.sqlite3",
        workspace_dir=tmp_path / "workspace",
    )
    private_key = ec.generate_private_key(ec.SECP256R1())
    envelope = _signed_envelope(
        private_key,
        "create file frontend-demo.txt content:hello from the frontend",
        "frontend-once",
        "frontend-browser-key",
    )
    public_key = _public_key_b64(private_key)

    registration = asyncio.run(_request(app, "POST", "/register-pubkey", {
        "pubkey_id": "frontend-browser-key",
        "public_key_b64": public_key,
    }))
    verified = asyncio.run(_request(app, "POST", "/api/prompt", envelope))
    executed = asyncio.run(_request(app, "POST", "/api/agent/execute", envelope))
    trace = asyncio.run(_request(app, "GET", f"/verify/{executed.json()['action_id']}"))

    assert registration.status_code == 201
    assert verified.status_code == 200
    assert executed.status_code == 200
    assert executed.json()["agent_draft"]["agent_type"] == "file"
    assert executed.json()["agent_draft"]["action_type"] == "file.create"
    assert (tmp_path / "workspace" / "frontend-demo.txt").read_text() == "hello from the frontend"
    assert trace.status_code == 200
    assert trace.json()["overall_valid"] is True


def test_frontend_style_database_prompt_is_not_treated_as_file(tmp_path):
    app = create_app(
        database_path=tmp_path / "aor.sqlite3",
        workspace_dir=tmp_path / "workspace",
    )
    private_key = ec.generate_private_key(ec.SECP256R1())
    envelope = _signed_envelope(
        private_key,
        "[Conversation: session | Context: Create a database named student…] create a database named student",
        "frontend-database-once",
        "frontend-database-key",
    )
    registration = asyncio.run(_request(app, "POST", "/register-pubkey", {
        "pubkey_id": "frontend-database-key",
        "public_key_b64": _public_key_b64(private_key),
    }))
    executed = asyncio.run(_request(app, "POST", "/api/agent/execute", envelope))

    assert registration.status_code == 201
    assert executed.status_code == 200
    assert executed.json()["agent_draft"]["agent_type"] == "database"
    assert executed.json()["agent_draft"]["action_type"] == "db.create"
    assert (tmp_path / "workspace" / "databases" / "student.sqlite3").is_file()
