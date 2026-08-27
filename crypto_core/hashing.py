"""SHA3-256 helpers for canonical AoR payloads."""

import hashlib
from typing import Any

from .canonical import canonicalize


def hash_sha3_256(data: bytes) -> bytes:
    """Return the SHA3-256 digest for *data* as 32 raw bytes."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return hashlib.sha3_256(data).digest()


def hash_payload(data: dict[str, Any]) -> bytes:
    """Canonicalize a payload with JCS, then return its SHA3-256 digest."""
    return hash_sha3_256(canonicalize(data))
