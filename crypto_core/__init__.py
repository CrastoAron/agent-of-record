"""Core cryptographic primitives for Agent-of-Record."""

from .canonical import canonicalize
from .hashing import hash_payload, hash_sha3_256
from .signing import (
    deserialize_private_key_pem,
    deserialize_private_key_raw,
    deserialize_public_key_pem,
    deserialize_public_key_raw,
    generate_keypair,
    serialize_private_key_pem,
    serialize_private_key_raw,
    serialize_public_key_pem,
    serialize_public_key_raw,
    sign,
    verify,
)

__all__ = [
    "canonicalize",
    "hash_payload",
    "hash_sha3_256",
    "generate_keypair",
    "sign",
    "verify",
    "serialize_private_key_raw",
    "deserialize_private_key_raw",
    "serialize_public_key_raw",
    "deserialize_public_key_raw",
    "serialize_private_key_pem",
    "deserialize_private_key_pem",
    "serialize_public_key_pem",
    "deserialize_public_key_pem",
]
