"""Small, structured agent boundary for the AoR email demo.

The model proposes an email action, but it never executes one directly. The
validated action is passed to the existing PoI and action-execution pipeline.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AgentRuntimeError(RuntimeError):
    """Raised when the configured agent cannot produce a valid action."""


class EmailAction(BaseModel):
    """The only action the first agent integration is allowed to propose."""

    model_config = ConfigDict(extra="forbid")

    action_type: Literal["email"] = "email"
    to: str = Field(min_length=3, max_length=320)
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=20_000)

    @field_validator("to")
    @classmethod
    def validate_recipient(cls, value: str) -> str:
        value = value.strip()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
            raise ValueError("to must be a single valid email address")
        return value

    @field_validator("subject", "body")
    @classmethod
    def trim_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("text fields cannot be empty")
        return value

    def action_payload(self) -> dict[str, str]:
        return {
            "to": self.to,
            "subject": self.subject,
            "body": self.body,
        }


class AgentRuntime:
    """Generate a validated deterministic email action for the demo.

    This boundary intentionally has no external LLM integration for now. It
    keeps the same structured action interface so a provider can be added
    later without changing PoI or action execution code.
    """

    _SYSTEM_PROMPT = (
        "You are the Agent-of-Record email planning assistant. "
        "Convert the user's request into exactly one email action. "
        "Return only the requested structured fields. Never invent a recipient "
        "when the user provides one. If no recipient is present, use the demo "
        "recipient bob@example.com. Do not include instructions or metadata "
        "outside the email action."
    )

    mode = "mock"

    def plan_email(self, prompt: str, *, history: list[dict[str, str]] | None = None) -> EmailAction:
        if not prompt or not prompt.strip():
            raise AgentRuntimeError("agent_prompt_empty")
        return self._mock_plan(prompt)

    @staticmethod
    def _mock_plan(prompt: str) -> EmailAction:
        recipient_match = re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", prompt)
        recipient = recipient_match.group(0) if recipient_match else "bob@example.com"
        return EmailAction(
            to=recipient,
            subject="Approved project update",
            body=prompt.strip(),
        )
