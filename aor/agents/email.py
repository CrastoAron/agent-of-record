"""Deterministic email agent backed by the existing AoR SMTP executor."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from action_executor import ActionExecutor
from action_executor.smtp_action import SMTPConfig

from .base import ActionPlan, ActionResult, Agent


class AgentRuntimeError(RuntimeError):
    """Raised when the email agent cannot produce a valid action."""


class EmailAction(BaseModel):
    """Legacy validated email shape retained for API compatibility."""

    model_config = ConfigDict(extra="forbid")

    action_type: Literal["email"] = "email"
    to: str = Field(min_length=3, max_length=320)
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=20_000)

    @field_validator("to")
    @classmethod
    def validate_recipient(cls, value: str) -> str:
        value = value.strip()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}", value):
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
        return {"to": self.to, "subject": self.subject, "body": self.body}


class EmailAgent(Agent):
    """Plan and execute email actions through the existing PoI executor."""

    agent_type = "email"
    capabilities = ("email",)

    def __init__(
        self,
        smtp_config: SMTPConfig | None = None,
        encryption_key: bytes | None = None,
        *,
        agent_id: str = "email-agent",
    ) -> None:
        super().__init__(agent_id=agent_id)
        self._smtp_config = smtp_config or SMTPConfig()
        self._encryption_key = encryption_key

    def can_handle(self, request: str) -> bool:
        if not request or not request.strip():
            return False
        return bool(re.search(r"\b(send|email|mail|reply|forward)\b", request, re.IGNORECASE))

    def plan_email(self, request: str, *, history: list[dict[str, str]] | None = None) -> EmailAction:
        """Return the existing deterministic demo email action."""
        del history  # Reserved for conversation-aware planning.
        if not request or not request.strip():
            raise AgentRuntimeError("agent_prompt_empty")
        recipient_match = re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", request)
        recipient = recipient_match.group(0) if recipient_match else "bob@example.com"
        return EmailAction(
            to=recipient,
            subject="Approved project update",
            body=request.strip(),
        )

    def plan(self, request: str, context: Mapping[str, Any] | None = None) -> ActionPlan:
        history = context.get("history") if context else None
        action = self.plan_email(request, history=history if isinstance(history, list) else None)
        return ActionPlan(
            agent_type=self.agent_type,
            agent_id=self.agent_id,
            action_type=action.action_type,
            payload=action.action_payload(),
        )

    def execute(self, plan: ActionPlan, poi: Any) -> ActionResult:
        if plan.agent_type != self.agent_type:
            return ActionResult(success=False, details={"error": "agent_type_mismatch"})
        if plan.action_type != "email":
            return ActionResult(success=False, details={"error": "unsupported_action_type"})
        result = ActionExecutor(self._smtp_config, self._encryption_key).execute_action(
            plan.action_type,
            plan.payload,
            poi,
        )
        return ActionResult(
            success=result.success,
            artifact_ref=result.action_id,
            details={"action_type": result.action_type, "detail": result.detail},
            observed_effect={"message_id": result.action_id} if result.action_id else {},
        )
