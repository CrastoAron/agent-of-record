from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest
import httpx
from cryptography.x509 import ObjectIdentifier

from tsa_anchor.anchor_scheduler import AnchorScheduler, AnchorStore, anchor_current_root
from tsa_anchor.config import TSAConfig, fetch_pinned_root_certificate, load_tsa_config
from tsa_anchor.models import TimestampToken
from tsa_anchor.tsa_client import TSAClient, TSARequestError
from tsa_anchor.tsa_verify import verify_timestamp_token


class _FakeImprint:
    message = b"imprint"
    hash_algorithm = ObjectIdentifier("2.16.840.1.101.3.4.2.1")


class _FakeInfo:
    gen_time = datetime(2026, 8, 27, 10, 0, tzinfo=timezone.utc)
    serial_number = 42
    message_imprint = _FakeImprint()


class _FakeResponse:
    status = 0
    status_string: list[str] = []
    tst_info = _FakeInfo()


def _config() -> TSAConfig:
    return TSAConfig("https://example.test/tsr", "https://example.test/ca.pem", "00" * 32)


def test_build_request_commits_sha256_of_stage2_root_bytes(ledger_root):
    request = TSAClient(_config()).build_request(ledger_root)

    assert request.cert_req is True
    assert request.message_imprint.message == hashlib.sha256(ledger_root).digest()


def test_request_retries_once_and_returns_parsed_token(monkeypatch, ledger_root):
    attempts = 0

    def post(_url, _content, _timeout):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise httpx.ConnectError("temporary failure")
        return b"time-stamp-response"

    monkeypatch.setattr("tsa_anchor.tsa_client.decode_timestamp_response", lambda _: _FakeResponse())
    token = TSAClient(_config(), post=post).request_timestamp(ledger_root)

    assert attempts == 2
    assert token.response_bytes == b"time-stamp-response"
    assert token.gen_time == _FakeInfo.gen_time
    assert token.serial_number == 42


def test_request_marks_failure_after_one_retry(ledger_root):
    def unavailable(_url, _content, _timeout):
        raise httpx.ConnectError("offline")

    with pytest.raises(TSARequestError, match="after one retry"):
        TSAClient(_config(), post=unavailable).request_timestamp(ledger_root)


class _RecordingClient:
    def __init__(self):
        self.calls: list[bytes] = []

    def request_timestamp(self, root: bytes) -> TimestampToken:
        self.calls.append(root)
        return TimestampToken(b"token", datetime.now(timezone.utc), len(self.calls), b"imprint", "2.16.840.1.101.3.4.2.1")


def test_anchor_current_root_and_scheduler_skip_unchanged_roots():
    from ledger_core import Ledger

    ledger = Ledger()
    ledger.append("user_prompt", {"text": "first"})
    client = _RecordingClient()
    store = AnchorStore()
    scheduler = AnchorScheduler(ledger, client=client, store=store, interval_seconds=1)

    first = scheduler.run_once()
    second = anchor_current_root(ledger, client=client, store=store)
    ledger.append("tool_result", {"text": "changed"})
    third = scheduler.run_once()

    assert first.status == second.status == third.status == "anchored"
    assert first is second
    assert len(client.calls) == 2
    assert first.ledger_root != third.ledger_root


@pytest.mark.network
def test_live_freetsa_request_returns_parseable_token(ledger_root):
    token = TSAClient().request_timestamp(ledger_root)
    root_ca = fetch_pinned_root_certificate(load_tsa_config())
    verified = verify_timestamp_token(token.response_bytes, ledger_root, root_ca)
    wrong_root = verify_timestamp_token(token.response_bytes, b"\x00" * 32, root_ca)
    corrupted = bytearray(token.response_bytes)
    corrupted[-1] ^= 1
    corrupt_result = verify_timestamp_token(bytes(corrupted), ledger_root, root_ca)

    assert token.response_bytes
    assert token.gen_time.tzinfo is not None
    assert token.hashed_message == hashlib.sha256(ledger_root).digest()
    assert verified.verified is True
    assert wrong_root.verified is False
    assert corrupt_result.verified is False
