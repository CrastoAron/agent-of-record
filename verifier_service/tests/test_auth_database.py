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


async def _request(app, method: str, path: str, *, payload=None, token: str | None = None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        return await client.request(method, path, json=payload, headers=headers)


def test_sqlite_auth_signup_login_and_session_restore(tmp_path):
    app = create_app(database_path=tmp_path / "aor.sqlite3")
    signup = asyncio.run(_request(app, "POST", "/api/auth/signup", payload={
        "name": "Ada Lovelace", "email": "Ada@Example.com", "password": "correct horse battery",
    }))

    assert signup.status_code == 201
    user = signup.json()["user"]
    token = signup.json()["token"]
    assert user["email"] == "ada@example.com"
    assert "password" not in user
    assert (tmp_path / "aor.sqlite3").exists()

    me = asyncio.run(_request(app, "GET", "/api/auth/me", token=token))
    assert me.status_code == 200
    assert me.json()["user"]["id"] == user["id"]

    login = asyncio.run(_request(app, "POST", "/api/auth/login", payload={
        "email": "ada@example.com", "password": "correct horse battery",
    }))
    assert login.status_code == 200
    assert login.json()["user"]["id"] == user["id"]

    duplicate = asyncio.run(_request(app, "POST", "/api/auth/signup", payload={
        "name": "Another Ada", "email": "ada@example.com", "password": "another password",
    }))
    assert duplicate.status_code == 400


def test_auth_logout_revokes_session(tmp_path):
    app = create_app(database_path=tmp_path / "aor.sqlite3")
    signup = asyncio.run(_request(app, "POST", "/api/auth/signup", payload={
        "name": "Grace Hopper", "email": "grace@example.com", "password": "password123",
    }))
    token = signup.json()["token"]

    logout = asyncio.run(_request(app, "POST", "/api/auth/logout", token=token))
    me = asyncio.run(_request(app, "GET", "/api/auth/me", token=token))

    assert logout.status_code == 200
    assert me.status_code == 401


def test_authenticated_prompt_is_persisted_with_artifact_and_trace(tmp_path):
    app = create_app(database_path=tmp_path / "aor.sqlite3")
    signup = asyncio.run(_request(app, "POST", "/api/auth/signup", payload={
        "name": "Prompt Owner", "email": "owner@example.com", "password": "password123",
    }))
    user = signup.json()["user"]
    token = signup.json()["token"]
    private_key = ec.generate_private_key(ec.SECP256R1())
    payload = {
        "prompt": "Send the approved update to Bob.",
        "user_id": user["id"],
        "session_id": "owner-session",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "nonce": "owner-prompt-once",
    }
    der_signature = private_key.sign(hash_payload(payload), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    envelope = {
        **payload,
        "signature": base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode(),
        "pubkey_id": "owner-browser-key",
    }
    public_key = base64.b64encode(private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )).decode()
    registration = asyncio.run(_request(app, "POST", "/register-pubkey", token=token, payload={
        "pubkey_id": "owner-browser-key", "public_key_b64": public_key,
    }))
    verified = asyncio.run(_request(app, "POST", "/api/prompt", token=token, payload=envelope))
    artifact = asyncio.run(_request(app, "POST", "/api/generate-artifact", token=token, payload=envelope))
    action_id = artifact.json()["action_id"]
    trace = asyncio.run(_request(app, "GET", f"/verify/{action_id}", token=token))
    history = asyncio.run(_request(app, "GET", "/api/prompts", token=token))

    assert registration.status_code == 201
    assert verified.status_code == 200
    assert artifact.status_code == 200
    assert trace.status_code == 200
    assert trace.json()["overall_valid"] is True
    assert history.status_code == 200
    assert history.json()["prompts"][0]["action_id"] == action_id
    assert history.json()["prompts"][0]["verification"]["overall_valid"] is True
