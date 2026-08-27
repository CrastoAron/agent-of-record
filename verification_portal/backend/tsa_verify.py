"""RFC 3161 verification seam; full anchoring arrives independently in Stage 9."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TimestampAnchorResult:
    verified: bool
    pending: bool
    detail: str


def verify_timestamp_token(timestamp_token: bytes | None, ledger_root: bytes) -> TimestampAnchorResult:
    """Report the Stage 9 anchor state without pretending an absent token passes.

    RFC 3161 CMS parsing, trusted TSA certificate validation, and covered-hash
    checks are intentionally deferred to Stage 9. Until then a missing token is
    an explicit pending state, not evidence of a timestamp.
    """
    if timestamp_token is None:
        return TimestampAnchorResult(False, True, "pending: no RFC 3161 timestamp token recorded")
    return TimestampAnchorResult(
        False,
        False,
        "timestamp token present but RFC 3161 validation is not configured until Stage 9",
    )
