"""Ed25519 key, signing, verification, and serialization helpers."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, SECP256R1, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Create a new Ed25519 private/public key pair."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def sign(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    """Sign *data* with an Ed25519 private key."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519PrivateKey")
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return private_key.sign(data)


def verify(public_key: Ed25519PublicKey | EllipticCurvePublicKey, signature: bytes, data: bytes) -> bool:
    """Return whether a supported public-key signature is valid.

    Ed25519 is the Stage 1 primitive. ECDSA P-256 support accepts the browser
    Web Crypto format used by Stage 3: a 64-byte raw ``r || s`` signature over
    ``data`` with ECDSA/SHA-256. It lets Stage 4 verify browser signatures
    without duplicating cryptographic verification logic.
    """
    if not isinstance(public_key, (Ed25519PublicKey, EllipticCurvePublicKey)):
        raise TypeError("public_key must be an Ed25519PublicKey or P-256 public key")
    if not isinstance(signature, bytes) or not isinstance(data, bytes):
        raise TypeError("signature and data must be bytes")
    try:
        if isinstance(public_key, Ed25519PublicKey):
            public_key.verify(signature, data)
        elif isinstance(public_key.curve, SECP256R1) and len(signature) == 64:
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            public_key.verify(
                encode_dss_signature(r, s),
                data,
                ECDSA(hashes.SHA256()),
            )
        else:
            return False
    except (InvalidSignature, ValueError):
        return False
    return True


def serialize_private_key_raw(private_key: Ed25519PrivateKey) -> bytes:
    """Serialize an Ed25519 private key as its 32-byte raw seed."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519PrivateKey")
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_private_key_raw(raw_key: bytes) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from its 32-byte raw seed."""
    if not isinstance(raw_key, bytes):
        raise TypeError("raw_key must be bytes")
    return Ed25519PrivateKey.from_private_bytes(raw_key)


def serialize_public_key_raw(public_key: Ed25519PublicKey) -> bytes:
    """Serialize an Ed25519 public key as its 32-byte raw form."""
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("public_key must be an Ed25519PublicKey")
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def deserialize_public_key_raw(raw_key: bytes) -> Ed25519PublicKey:
    """Load an Ed25519 public key from its 32-byte raw form."""
    if not isinstance(raw_key, bytes):
        raise TypeError("raw_key must be bytes")
    return Ed25519PublicKey.from_public_bytes(raw_key)


def serialize_private_key_pem(private_key: Ed25519PrivateKey) -> bytes:
    """Serialize an Ed25519 private key as unencrypted PKCS#8 PEM."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519PrivateKey")
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_private_key_pem(pem_key: bytes) -> Ed25519PrivateKey:
    """Load an unencrypted Ed25519 private key from PKCS#8 PEM."""
    if not isinstance(pem_key, bytes):
        raise TypeError("pem_key must be bytes")
    key = serialization.load_pem_private_key(pem_key, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("PEM does not contain an Ed25519 private key")
    return key


def serialize_public_key_pem(public_key: Ed25519PublicKey) -> bytes:
    """Serialize an Ed25519 public key as SubjectPublicKeyInfo PEM."""
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("public_key must be an Ed25519PublicKey")
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key_pem(pem_key: bytes) -> Ed25519PublicKey:
    """Load an Ed25519 public key from SubjectPublicKeyInfo PEM."""
    if not isinstance(pem_key, bytes):
        raise TypeError("pem_key must be bytes")
    key = serialization.load_pem_public_key(pem_key)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("PEM does not contain an Ed25519 public key")
    return key
