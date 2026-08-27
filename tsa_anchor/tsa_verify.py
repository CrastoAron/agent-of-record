"""Cryptographic RFC 3161 timestamp-response verification."""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from rfc3161_client import VerificationError, VerifierBuilder, decode_timestamp_response

from .models import TimestampVerificationResult


def _load_certificate(value: x509.Certificate | bytes | Path) -> x509.Certificate:
    if isinstance(value, x509.Certificate):
        return value
    certificate_bytes = value.read_bytes() if isinstance(value, Path) else value
    try:
        return x509.load_pem_x509_certificate(certificate_bytes)
    except ValueError:
        return x509.load_der_x509_certificate(certificate_bytes)


def verify_timestamp_token(
    token_bytes: bytes, expected_hash: bytes, tsa_root_cert: x509.Certificate | bytes | Path
) -> TimestampVerificationResult:
    """Verify signer chain, CMS signature, and the root bytes bound by a token.

    ``expected_hash`` is the Stage 2 SHA3 Merkle root. The verifier computes
    the digest required by the token's declared RFC 3161 imprint algorithm and
    compares it with the embedded ``hashedMessage`` as part of verification.
    """
    if not isinstance(expected_hash, bytes) or len(expected_hash) != 32:
        return TimestampVerificationResult(False, None, "expected ledger root must be 32 bytes")
    try:
        root_cert = _load_certificate(tsa_root_cert)
        response = decode_timestamp_response(token_bytes)
        verifier = VerifierBuilder().add_root_certificate(root_cert).build()
        verifier.verify_message(response, expected_hash)
        return TimestampVerificationResult(
            True,
            response.tst_info.gen_time,
            "RFC 3161 signature chain and ledger-root message imprint verified",
            response.tst_info.message_imprint.message,
        )
    except (VerificationError, ValueError, TypeError) as exc:
        return TimestampVerificationResult(False, None, f"RFC 3161 verification failed: {exc}")
