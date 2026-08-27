from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from key_registry import KeyRegistry
from key_registry.jwks import import_jwk
from key_registry.storage import SQLiteKeyStorage


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ed25519_public_bytes() -> bytes:
    return Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def test_jwks_exports_only_currently_active_keys() -> None:
    registry = KeyRegistry(SQLiteKeyStorage())
    active_key = _ed25519_public_bytes()
    registry.register_key("agent-a", "active", active_key, "Ed25519", _now())
    registry.register_key(
        "agent-a", "expired", _ed25519_public_bytes(), "Ed25519", _now() - timedelta(minutes=2), _now() - timedelta(minutes=1)
    )
    registry.register_key("agent-b", "revoked", _ed25519_public_bytes(), "Ed25519", _now())
    registry.revoke_key("revoked")

    jwks = registry.export_jwks()

    assert [jwk["kid"] for jwk in jwks["keys"]] == ["active"]
    assert jwks["keys"][0]["kty"] == "OKP"
    assert jwks["keys"][0]["crv"] == "Ed25519"


def test_ed25519_jwk_export_and_import_round_trip() -> None:
    registry = KeyRegistry(SQLiteKeyStorage())
    public_key_bytes = _ed25519_public_bytes()
    registry.register_key("agent-a", "ed-key", public_key_bytes, "Ed25519", _now())

    exported_jwk = registry.export_jwks()["keys"][0]

    assert import_jwk(exported_jwk) == public_key_bytes
