"""Fixtures for offline RFC 3161 adapter tests."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@pytest.fixture
def ledger_root() -> bytes:
    return bytes.fromhex("c4" * 32)


@pytest.fixture
def root_certificate() -> x509.Certificate:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AoR Test TSA Root")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2035, 1, 1, tzinfo=timezone.utc))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )


@pytest.fixture
def root_certificate_pem(root_certificate: x509.Certificate) -> bytes:
    return root_certificate.public_bytes(serialization.Encoding.PEM)
