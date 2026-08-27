"""AES-256-GCM protection for optional user-supplied audit rationale."""

from __future__ import annotations

import base64
import os
from typing import TypedDict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptedReasoning(TypedDict):
    ciphertext: str
    nonce: str
    tag: str


def generate_encryption_key() -> bytes:
    """Generate a 32-byte AES-256 key for a local demo.

    Production uses KMS/HSM-derived key material alongside the agent signing
    key; this function is never a substitute for durable key custody.
    """
    return AESGCM.generate_key(bit_length=256)


def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")


def encrypt_cot(reasoning_text: str, key: bytes) -> EncryptedReasoning:
    """Encrypt optional audit rationale with AES-256-GCM.

    The executor never derives or exposes private model reasoning; callers may
    provide a deliberate, reviewable rationale string if their policy permits.
    """
    _validate_key(key)
    nonce = os.urandom(12)
    combined = AESGCM(key).encrypt(nonce, reasoning_text.encode("utf-8"), None)
    ciphertext, tag = combined[:-16], combined[-16:]
    return {
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }


def decrypt_cot(encrypted: EncryptedReasoning, key: bytes) -> str:
    """Decrypt an AES-256-GCM rationale; invalid tags/keys raise an exception."""
    _validate_key(key)
    nonce = base64.b64decode(encrypted["nonce"], validate=True)
    ciphertext = base64.b64decode(encrypted["ciphertext"], validate=True)
    tag = base64.b64decode(encrypted["tag"], validate=True)
    return AESGCM(key).decrypt(nonce, ciphertext + tag, None).decode("utf-8")
