"""Transport-safe model for the signed AoR Proof of Intent artifact."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ProofOfIntent(BaseModel):
    """A signed commitment to an action immediately before it executes.

    Hashes and signatures are lowercase hexadecimal strings to make the artifact
    convenient to place in later action headers and verification reports.
    """

    user_prompt_hash: str = Field(min_length=64, max_length=64)
    system_prompt_hash: str = Field(min_length=64, max_length=64)
    context_root: str = Field(min_length=64, max_length=64)
    action_payload_hash: str = Field(min_length=64, max_length=64)
    model_id: str = Field(min_length=1)
    timestamp: str = Field(min_length=1)
    nonce: str = Field(min_length=1)
    agent_signature: str | None = None
    agent_pubkey_id: str | None = None

    def signing_payload(self) -> dict[str, str | None]:
        """Return all fields bound by the agent signature except the signature itself."""
        return self.model_dump(exclude={"agent_signature"})
