"""Validated request models for the temporary AoR verifier API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class SignedEnvelope(BaseModel):
    """The signed transport envelope emitted by the Stage 3 browser client."""

    # Ignore UI-only diagnostics such as canonical_payload_hex. The verifier
    # always recomputes them and does not trust transport-provided values.
    model_config = ConfigDict(extra="ignore")

    prompt: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    timestamp: str = Field(min_length=1)
    nonce: str = Field(min_length=1)
    signature: str = Field(min_length=1)
    pubkey_id: str = Field(min_length=1)
    signature_algorithm: str = "ECDSA-P256-SHA256"

    def signing_payload(self) -> dict[str, str]:
        """Return exactly the five fields Stage 3 covered with its signature."""
        return {
            "prompt": self.prompt,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
        }


class PubkeyRegistration(BaseModel):
    """Temporary public-key registration request until Stage 5's registry."""

    pubkey_id: str = Field(min_length=1)
    public_key_b64: str | None = None
    public_key_jwk: dict[str, Any] | None = None

    @model_validator(mode="after")
    def exactly_one_key_representation(self) -> "PubkeyRegistration":
        if (self.public_key_b64 is None) == (self.public_key_jwk is None):
            raise ValueError("provide exactly one of public_key_b64 or public_key_jwk")
        return self
