"""Outbound action wrappers that attach a signed AoR Proof of Intent."""

from .executor import ActionExecutor, ActionResult
from .smtp_action import SMTPConfig, send_email_with_proof

__all__ = ["ActionExecutor", "ActionResult", "SMTPConfig", "send_email_with_proof"]
