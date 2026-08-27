"""HTTPS RFC 3161 client for anchoring an AoR Merkle-root value."""

from __future__ import annotations

from collections.abc import Callable

import httpx
from rfc3161_client import (
    HashAlgorithm,
    PKIStatus,
    TimestampRequestBuilder,
    decode_timestamp_response,
)

from .config import TSAConfig, load_tsa_config
from .models import TimestampToken


class TSARequestError(RuntimeError):
    """A TSA was unavailable or returned an invalid/ungranted response."""


PostFunction = Callable[[str, bytes, float], bytes]


def _https_post(url: str, content: bytes, timeout_seconds: float) -> bytes:
    response = httpx.post(
        url,
        content=content,
        headers={"Content-Type": "application/timestamp-query", "Accept": "application/timestamp-reply"},
        timeout=timeout_seconds,
        follow_redirects=False,
    )
    response.raise_for_status()
    return response.content


class TSAClient:
    """Build, send, retry once, and parse standards-compliant timestamp requests."""

    def __init__(self, config: TSAConfig | None = None, post: PostFunction | None = None) -> None:
        self.config = config or load_tsa_config()
        self._post = post or _https_post

    def build_request(self, data_hash: bytes):
        """Build a certificate-requesting RFC 3161 request over Merkle-root bytes.

        Stage 2 roots are SHA3-256 values. FreeTSA supports SHA-256 but not
        SHA3 message-imprint OIDs, so its standard SHA-256 imprint commits to
        the *32 root bytes*. Verification re-hashes the supplied root using the
        token-declared imprint algorithm and compares that exact digest.
        """
        if not isinstance(data_hash, bytes) or len(data_hash) != 32:
            raise ValueError("ledger root must be a 32-byte SHA3-256 digest")
        try:
            algorithm = HashAlgorithm[self.config.request_hash_algorithm]
        except KeyError as exc:
            raise ValueError("configured RFC 3161 request hash is unsupported") from exc
        return (
            TimestampRequestBuilder()
            .data(data_hash)
            .hash_algorithm(algorithm)
            .cert_request(cert_request=True)
            .build()
        )

    def request_timestamp(self, data_hash: bytes) -> TimestampToken:
        """Request an RFC 3161 timestamp, retrying exactly once on failure."""
        request = self.build_request(data_hash)
        last_error: Exception | None = None
        for _attempt in range(2):
            try:
                response_bytes = self._post(
                    self.config.endpoint, request.as_bytes(), self.config.timeout_seconds
                )
                response = decode_timestamp_response(response_bytes)
                if PKIStatus(response.status) != PKIStatus.GRANTED:
                    raise TSARequestError(
                        "TSA did not grant the request: " + "; ".join(response.status_string)
                    )
                info = response.tst_info
                return TimestampToken(
                    response_bytes=response_bytes,
                    gen_time=info.gen_time,
                    serial_number=info.serial_number,
                    hashed_message=info.message_imprint.message,
                    hash_algorithm_oid=info.message_imprint.hash_algorithm.dotted_string,
                )
            except (httpx.HTTPError, ValueError, TSARequestError) as exc:
                last_error = exc
        raise TSARequestError(f"TSA request failed after one retry: {last_error}") from last_error


def request_timestamp(data_hash: bytes) -> TimestampToken:
    """Request a timestamp using the source-controlled default TSA configuration."""
    return TSAClient().request_timestamp(data_hash)
