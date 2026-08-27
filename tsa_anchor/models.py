"""Transport and storage models for RFC 3161 ledger-root anchors."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal


@dataclass(frozen=True)
class TimestampToken:
    """A decoded RFC 3161 TimeStampResp, retained in raw form for later audit."""

    response_bytes: bytes
    gen_time: datetime
    serial_number: int
    # The RFC 3161 message imprint. For FreeTSA this is SHA-256(root bytes).
    hashed_message: bytes
    hash_algorithm_oid: str


@dataclass(frozen=True)
class TimestampVerificationResult:
    verified: bool
    gen_time: datetime | None
    detail: str
    hashed_message: bytes | None = None


@dataclass(frozen=True)
class AnchorRecord:
    """An immutable record of one attempt to anchor a specific ledger root."""

    ledger_root: bytes
    token_bytes: bytes | None
    gen_time: datetime | None
    anchored_at: datetime
    status: Literal["anchored", "pending", "failed"]
    detail: str = ""
