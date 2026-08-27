from __future__ import annotations

from datetime import datetime, timezone

from cryptography.x509 import ObjectIdentifier

from tsa_anchor.tsa_verify import verify_timestamp_token


class _FakeImprint:
    message = b"verified-imprint"
    hash_algorithm = ObjectIdentifier("2.16.840.1.101.3.4.2.1")


class _FakeInfo:
    gen_time = datetime(2026, 8, 27, 10, 0, tzinfo=timezone.utc)
    message_imprint = _FakeImprint()


class _FakeResponse:
    tst_info = _FakeInfo()


class _FakeVerifier:
    def __init__(self, expected_hash: bytes):
        self.expected_hash = expected_hash

    def verify_message(self, _response, message: bytes):
        if message != self.expected_hash:
            from rfc3161_client import VerificationError
            raise VerificationError("Mismatch between messages")
        return True


class _FakeVerifierBuilder:
    expected_hash = b""

    def add_root_certificate(self, _certificate):
        return self

    def build(self):
        return _FakeVerifier(self.expected_hash)


def _install_verified_response(monkeypatch, expected_hash: bytes):
    _FakeVerifierBuilder.expected_hash = expected_hash
    monkeypatch.setattr("tsa_anchor.tsa_verify.decode_timestamp_response", lambda _: _FakeResponse())
    monkeypatch.setattr("tsa_anchor.tsa_verify.VerifierBuilder", _FakeVerifierBuilder)


def test_verify_timestamp_token_succeeds_for_matching_root(monkeypatch, ledger_root, root_certificate_pem):
    _install_verified_response(monkeypatch, ledger_root)

    result = verify_timestamp_token(b"genuine-shaped-token", ledger_root, root_certificate_pem)

    assert result.verified is True
    assert result.gen_time == _FakeInfo.gen_time
    assert result.hashed_message == b"verified-imprint"


def test_verify_timestamp_token_rejects_different_root(monkeypatch, ledger_root, root_certificate):
    _install_verified_response(monkeypatch, ledger_root)

    result = verify_timestamp_token(b"genuine-shaped-token", b"\x01" * 32, root_certificate)

    assert result.verified is False
    assert "Mismatch" in result.detail


def test_verify_timestamp_token_rejects_corrupt_token(monkeypatch, ledger_root, root_certificate):
    def corrupt(_token):
        raise ValueError("invalid TimeStampResp")

    monkeypatch.setattr("tsa_anchor.tsa_verify.decode_timestamp_response", corrupt)

    result = verify_timestamp_token(b"\x00corrupted", ledger_root, root_certificate)

    assert result.verified is False
    assert "invalid TimeStampResp" in result.detail
