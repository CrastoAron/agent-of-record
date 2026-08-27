"""Demo-only agent Ed25519 key custody, separate from user/browser keys."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from crypto_core import (
    deserialize_private_key_pem,
    generate_keypair,
    hash_sha3_256,
    serialize_private_key_pem,
    serialize_public_key_raw,
)
from key_registry import KeyRegistry

DEFAULT_KEY_DIRECTORY = Path(".aor_agent_keys")


def _key_file(agent_id: str, key_directory: Path) -> Path:
    if not agent_id:
        raise ValueError("agent_id must be a non-empty string")
    # A digest avoids treating caller-controlled agent IDs as filesystem paths.
    identifier = hash_sha3_256(agent_id.encode("utf-8")).hex()
    return key_directory / f"{identifier}.pem"


def load_agent_keypair(
    agent_id: str, key_directory: Path = DEFAULT_KEY_DIRECTORY
) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Load or generate a demo agent key pair, persisted as a 0600 PEM file.

    This is intentionally plain PEM for the local demo only. Production agent
    private keys must live in KMS/HSM-backed custody, never in this filesystem.
    """
    key_path = _key_file(agent_id, key_directory)
    if key_path.exists():
        private_key = deserialize_private_key_pem(key_path.read_bytes())
        return private_key, private_key.public_key()

    key_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_key, public_key = generate_keypair()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        file_descriptor = os.open(key_path, flags, 0o600)
    except FileExistsError:
        # Another worker generated the same agent key between exists() and open().
        private_key = deserialize_private_key_pem(key_path.read_bytes())
        return private_key, private_key.public_key()
    with os.fdopen(file_descriptor, "wb") as output:
        output.write(serialize_private_key_pem(private_key))
    return private_key, public_key


def agent_pubkey_id(private_key: Ed25519PrivateKey) -> str:
    """Derive the stable Stage 5 public-key ID for an agent private key."""
    raw_public_key = serialize_public_key_raw(private_key.public_key())
    return f"agent-ed25519-{hash_sha3_256(raw_public_key).hex()}"


def register_agent_public_key(
    agent_id: str,
    registry: KeyRegistry,
    private_key: Ed25519PrivateKey,
) -> str:
    """Register the agent's public half when absent from the Stage 5 registry."""
    pubkey_id = agent_pubkey_id(private_key)
    public_key_bytes = serialize_public_key_raw(private_key.public_key())
    if registry.get_pubkey(pubkey_id) == public_key_bytes:
        return pubkey_id
    try:
        registry.register_key(
            agent_id=agent_id,
            pubkey_id=pubkey_id,
            public_key_bytes=public_key_bytes,
            algorithm="Ed25519",
            valid_from=datetime.now(timezone.utc),
        )
    except ValueError as exc:
        # A duplicate can only be reused safely when it is the same key.
        if "already registered" not in str(exc):
            raise
    return pubkey_id
