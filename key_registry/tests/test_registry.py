import base64
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from crypto_core import hash_payload
from key_registry import KeyRegistry
from key_registry.storage import SQLiteKeyStorage
from verifier_service.models import SignedEnvelope
from verifier_service.nonce_store import NonceStore
from verifier_service.verifier import SignatureVerifier


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _public_key_bytes() -> bytes:
    return Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _registry() -> KeyRegistry:
    return KeyRegistry(SQLiteKeyStorage())


def test_registered_active_key_is_retrieved() -> None:
    registry = _registry()
    public_key_bytes = _public_key_bytes()
    registry.register_key("agent-1", "key-1", public_key_bytes, "Ed25519", _now())

    assert registry.get_pubkey("key-1") == public_key_bytes


def test_expired_key_is_not_retrieved() -> None:
    registry = _registry()
    registry.register_key(
        "agent-1", "expired", _public_key_bytes(), "Ed25519", _now() - timedelta(minutes=2), _now() - timedelta(minutes=1)
    )

    assert registry.get_pubkey("expired") is None


def test_revoked_key_is_not_retrieved() -> None:
    registry = _registry()
    registry.register_key("agent-1", "revoked", _public_key_bytes(), "Ed25519", _now())

    assert registry.revoke_key("revoked")
    assert registry.get_pubkey("revoked") is None


def test_list_active_keys_excludes_expired_and_revoked_records() -> None:
    registry = _registry()
    registry.register_key("agent-1", "active", _public_key_bytes(), "Ed25519", _now())
    registry.register_key("agent-1", "expired", _public_key_bytes(), "Ed25519", _now() - timedelta(minutes=2), _now() - timedelta(minutes=1))
    registry.register_key("agent-1", "revoked", _public_key_bytes(), "Ed25519", _now())
    registry.revoke_key("revoked")

    assert [record.pubkey_id for record in registry.list_active_keys("agent-1")] == ["active"]


def test_stage4_verifier_accepts_a_key_from_the_new_registry() -> None:
    registry = _registry()
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    registry.register_key("email-agent", "p256-key", public_key_bytes, "ECDSA-P256-SHA256", _now())
    payload = {
        "prompt": "send an email to bob@example.com",
        "user_id": "u123",
        "session_id": "s123",
        "timestamp": _now().isoformat().replace("+00:00", "Z"),
        "nonce": "registry-regression-nonce",
    }
    der_signature = private_key.sign(hash_payload(payload), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    envelope = SignedEnvelope(
        **payload,
        signature=base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode(),
        pubkey_id="p256-key",
    )

    result = SignatureVerifier(registry, NonceStore()).verify_envelope(envelope)

    assert result.valid
