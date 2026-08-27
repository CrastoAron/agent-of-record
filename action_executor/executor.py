"""Single dispatch boundary that binds a signed PoI before any outbound action."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from crypto_core import hash_payload
from poi_generator.models import ProofOfIntent

from .jwt_action import execute_jwt_action
from .smtp_action import SMTPConfig, send_email_with_proof


@dataclass(frozen=True)
class ActionResult:
    success: bool
    action_type: str
    action_id: str | None = None
    detail: str | None = None


class ActionExecutor:
    """Dispatch actions only after asserting their exact payload matches the PoI."""

    def __init__(self, smtp_config: SMTPConfig, encryption_key: bytes | None = None) -> None:
        self._smtp_config = smtp_config
        self._encryption_key = encryption_key

    def execute_action(
        self, action_type: str, action_payload: dict[str, Any], poi: ProofOfIntent
    ) -> ActionResult:
        """Route email actions through the PoI-attaching SMTP wrapper.

        The payload-hash guard prevents a caller from attaching a valid PoI to a
        changed email body or destination.
        """
        if hash_payload(action_payload).hex() != poi.action_payload_hash:
            return ActionResult(False, action_type, detail="action_payload_hash_mismatch")
        if action_type == "email":
            required_fields = {"to", "subject", "body"}
            if not required_fields.issubset(action_payload):
                return ActionResult(False, action_type, detail="missing_email_fields")
            message_id = send_email_with_proof(
                action_payload["to"],
                action_payload["subject"],
                action_payload["body"],
                poi,
                self._smtp_config,
                reasoning_text=action_payload.get("audit_rationale"),
                encryption_key=self._encryption_key,
            )
            return ActionResult(True, action_type, action_id=message_id)
        if action_type in {"trade", "db"}:
            execute_jwt_action(action_type, action_payload, poi)
        return ActionResult(False, action_type, detail="unsupported_action_type")
