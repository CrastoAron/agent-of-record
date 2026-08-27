"""Pydantic data models for public-key registry records and API requests."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(timezone.utc)


class AgentKeyRecord(BaseModel):
    """A registered public key and the time window in which it is usable."""

    agent_id: str = Field(min_length=1)
    pubkey_id: str = Field(min_length=1)
    public_key_bytes: bytes = Field(min_length=1)
    algorithm: str = Field(min_length=1)
    valid_from: datetime
    valid_until: datetime | None = None
    revoked: bool = False
    created_at: datetime

    @field_validator("valid_from", "valid_until", "created_at")
    @classmethod
    def timestamps_must_be_aware(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _as_utc(value)

    @model_validator(mode="after")
    def validity_window_is_ordered(self) -> "AgentKeyRecord":
        if self.valid_until is not None and self.valid_until < self.valid_from:
            raise ValueError("valid_until must be at or after valid_from")
        return self


class RegisterKeyRequest(BaseModel):
    """HTTP request used by the Stage 5 key-registration endpoint."""

    agent_id: str = Field(min_length=1)
    pubkey_id: str = Field(min_length=1)
    algorithm: str = Field(min_length=1)
    public_key_b64: str | None = None
    public_key_jwk: dict[str, Any] | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None

    @field_validator("valid_from", "valid_until")
    @classmethod
    def optional_timestamps_must_be_aware(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _as_utc(value)

    @model_validator(mode="after")
    def validate_key_and_window(self) -> "RegisterKeyRequest":
        if (self.public_key_b64 is None) == (self.public_key_jwk is None):
            raise ValueError("provide exactly one of public_key_b64 or public_key_jwk")
        if self.valid_from and self.valid_until and self.valid_until < self.valid_from:
            raise ValueError("valid_until must be at or after valid_from")
        return self


class RevokeKeyRequest(BaseModel):
    """HTTP request for a public-key revocation."""

    pubkey_id: str = Field(min_length=1)
