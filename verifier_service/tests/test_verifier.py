from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient

from crypto_core import hash_payload
from verifier_service.main import create_app
from verifier_service.models import SignedEnvelope
from verifier_service.nonce_store import NonceStore
from verifier_service.pubkey_store import PubkeyStore
from verifier_service.verifier import SignatureVerifier


def _timestamp(offset_seconds: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).isoformat().replace(
        "+00:00", "Z"
    )


def _raw_webcrypto_signature(private_key: ec.EllipticCurvePrivateKey, payload: dict[str, str]) -> str:
    der_signature = private_key.sign(hash_payload(payload), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return base64.b64encode(raw_signature).decode("ascii")


def _make_envelope(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    nonce: str = "nonce-1",
    timestamp: str | None = None,
    pubkey_id: str = "p256-test-key",
) -> SignedEnvelope:
    payload = {
        "prompt": "send an email to bob@example.com",
        "user_id": "u123",
        "session_id": "s123",
        "timestamp": timestamp or _timestamp(),
        "nonce": nonce,
    }
    return SignedEnvelope(
        **payload,
        signature=_raw_webcrypto_signature(private_key, payload),
        pubkey_id=pubkey_id,
    )


def _register_key(store: PubkeyStore, key_id: str, private_key: ec.EllipticCurvePrivateKey) -> None:
    store.register_pubkey(
        key_id,
        private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _verifier_with_key(private_key: ec.EllipticCurvePrivateKey) -> SignatureVerifier:
    pubkey_store = PubkeyStore()
    _register_key(pubkey_store, "p256-test-key", private_key)
    return SignatureVerifier(pubkey_store, NonceStore())


def test_valid_fresh_envelope_is_verified() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    result = _verifier_with_key(private_key).verify_envelope(_make_envelope(private_key))

    assert result.valid
    assert result.reason is None


def test_stale_timestamp_is_rejected_before_other_checks() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    envelope = _make_envelope(private_key, timestamp=_timestamp(-61))

    result = _verifier_with_key(private_key).verify_envelope(envelope)

    assert not result.valid
    assert result.reason == "timestamp_stale"


def test_replayed_nonce_is_rejected() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    verifier = _verifier_with_key(private_key)
    envelope = _make_envelope(private_key, nonce="once-only")

    assert verifier.verify_envelope(envelope).valid
    replay_result = verifier.verify_envelope(envelope)

    assert not replay_result.valid
    assert replay_result.reason == "nonce_reused"


def test_unknown_public_key_is_rejected() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    envelope = _make_envelope(private_key, pubkey_id="not-registered")

    result = SignatureVerifier(PubkeyStore(), NonceStore()).verify_envelope(envelope)

    assert not result.valid
    assert result.reason == "unknown_pubkey"


def test_tampered_prompt_is_rejected_as_signature_mismatch() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    envelope = _make_envelope(private_key)
    tampered = envelope.model_copy(update={"prompt": "delete all contacts"})

    result = _verifier_with_key(private_key).verify_envelope(tampered)

    assert not result.valid
    assert result.reason == "signature_mismatch"


def test_signature_checked_against_wrong_registered_key_is_rejected() -> None:
    signer = ec.generate_private_key(ec.SECP256R1())
    wrong_key = ec.generate_private_key(ec.SECP256R1())
    pubkey_store = PubkeyStore()
    _register_key(pubkey_store, "p256-test-key", wrong_key)

    result = SignatureVerifier(pubkey_store, NonceStore()).verify_envelope(_make_envelope(signer))

    assert not result.valid
    assert result.reason == "signature_mismatch"


def test_api_rejection_is_generic_and_never_calls_downstream_handler() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    downstream = Mock()
    app = create_app(on_verified=downstream)
    client = TestClient(app)
    envelope = _make_envelope(private_key, pubkey_id="unknown")

    response = client.post("/api/prompt", json=envelope.model_dump())

    assert response.status_code == 401
    assert response.json() == {"detail": "verification_failed"}
    downstream.assert_not_called()


def test_api_register_then_verify_and_reject_replay() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    app = create_app()
    client = TestClient(app)
    public_key_b64 = base64.b64encode(
        private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode("ascii")
    envelope = _make_envelope(private_key)

    registration = client.post(
        "/register-pubkey",
        json={"pubkey_id": envelope.pubkey_id, "public_key_b64": public_key_b64},
    )
    verified = client.post("/api/prompt", json=envelope.model_dump())
    replayed = client.post("/api/prompt", json=envelope.model_dump())

    assert registration.status_code == 201
    assert verified.status_code == 200
    assert verified.json()["status"] == "verified"
    assert replayed.status_code == 401
    assert replayed.json() == {"detail": "verification_failed"}


def test_api_accepts_the_stage3_p256_jwk_registration_format() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    stage3_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _base64url(numbers.x.to_bytes(32, "big")),
        "y": _base64url(numbers.y.to_bytes(32, "big")),
    }
    app = create_app()
    client = TestClient(app)
    envelope = _make_envelope(private_key)

    registration = client.post(
        "/register-pubkey",
        json={"pubkey_id": envelope.pubkey_id, "public_key_jwk": stage3_jwk},
    )
    verified = client.post("/api/prompt", json=envelope.model_dump())

    assert registration.status_code == 201
    assert verified.status_code == 200
