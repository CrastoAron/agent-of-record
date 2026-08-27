"""Stage 8 adapter around Stage 9's cryptographic RFC 3161 verifier."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TimestampAnchorResult:
    verified: bool
    pending: bool
    detail: str


def verify_timestamp_token(timestamp_token: bytes | None, ledger_root: bytes) -> TimestampAnchorResult:
    """Verify an anchored ledger root or make a truthful pending report.

    Stage 9 keeps the TSA endpoint and pinned CA digest in its configuration;
    importing it here makes the portal's sixth link fully cryptographic without
    duplicating ASN.1/CMS parsing logic.
    """
    if timestamp_token is None:
        return TimestampAnchorResult(False, True, "pending: no RFC 3161 timestamp token recorded")
    try:
        from tsa_anchor.config import fetch_pinned_root_certificate, load_tsa_config
        from tsa_anchor.tsa_verify import verify_timestamp_token as verify_rfc3161_token

        verification = verify_rfc3161_token(
            timestamp_token, ledger_root, fetch_pinned_root_certificate(load_tsa_config())
        )
    except Exception as exc:
        return TimestampAnchorResult(False, False, f"RFC 3161 verification unavailable: {exc}")
    if not verification.verified:
        return TimestampAnchorResult(False, False, verification.detail)
    assert verification.gen_time is not None
    return TimestampAnchorResult(True, False, f"verified, anchored at {verification.gen_time.isoformat()}")
