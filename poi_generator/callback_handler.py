"""LangChain pre-tool callback that creates a signed PoI before execution."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from langchain_core.callbacks import BaseCallbackHandler

from key_registry import KeyRegistry
from ledger_core import Ledger

from .agent_keys import load_agent_keypair, register_agent_public_key
from .models import ProofOfIntent
from .poi import build_poi, sign_poi


class MissingVerifiedSessionContext(RuntimeError):
    """Raised when a tool call cannot be tied to a Stage 4-verified request."""


@dataclass(frozen=True)
class VerifiedSessionContext:
    """Request-scoped data populated only after Stage 4 verification succeeds."""

    session_id: str
    user_prompt: str
    system_prompt: str
    ledger: Ledger
    model_id: str


class PoICallbackHandler(BaseCallbackHandler):
    """Build, sign, and store one PoI at LangChain's pre-tool execution hook.

    Targeted against langchain-core 1.5's callback signature:
    ``on_tool_start(serialized, input_str, *, run_id, parent_run_id=None,
    tags=None, metadata=None, inputs=None, **kwargs)``.
    """

    raise_error = True
    run_inline = True

    def __init__(
        self,
        verified_sessions: dict[str, VerifiedSessionContext] | None = None,
        agent_private_key: Ed25519PrivateKey | None = None,
        *,
        agent_id: str | None = None,
        registry: KeyRegistry | None = None,
    ) -> None:
        super().__init__()
        self._sessions = dict(verified_sessions or {})
        if agent_private_key is None:
            if not agent_id or registry is None:
                raise ValueError("agent_id and registry are required when loading an agent key")
            agent_private_key, _ = load_agent_keypair(agent_id)
            register_agent_public_key(agent_id, registry, agent_private_key)
        elif agent_id and registry:
            register_agent_public_key(agent_id, registry, agent_private_key)
        self._agent_private_key = agent_private_key
        self._pois_by_run_id: dict[str, ProofOfIntent] = {}

    def register_verified_session(self, context: VerifiedSessionContext) -> None:
        """Associate a verified request context with its LangChain session ID."""
        self._sessions[context.session_id] = context

    def get_poi(self, run_id: UUID | str) -> ProofOfIntent:
        """Return the PoI produced for a tool run, for Stage 7 consumption."""
        return self._pois_by_run_id[str(run_id)]

    @staticmethod
    def _action_payload(input_str: str) -> dict[str, Any]:
        """Preserve a JSON tool input as a dict, or bind the exact raw text."""
        try:
            decoded = json.loads(input_str)
        except json.JSONDecodeError:
            return {"input": input_str}
        return decoded if isinstance(decoded, dict) else {"input": input_str}

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Create a PoI before a tool executes, then append its call to the ledger."""
        session_id = (metadata or {}).get("session_id")
        context = self._sessions.get(session_id) if isinstance(session_id, str) else None
        if context is None:
            raise MissingVerifiedSessionContext(
                "tool execution blocked: no verified session context in callback metadata"
            )

        action_payload = self._action_payload(input_str)
        # The root is captured before the tool call itself is added. The append
        # below ensures the action becomes authenticated context for later calls.
        poi = sign_poi(
            build_poi(
                context.user_prompt,
                context.system_prompt,
                context.ledger,
                action_payload,
                context.model_id,
            ),
            self._agent_private_key,
        )
        self._pois_by_run_id[str(run_id)] = poi
        context.ledger.append(
            "tool_call",
            {
                "tool_name": serialized.get("name") or serialized.get("id") or "unknown_tool",
                "input": action_payload,
                "run_id": str(run_id),
            },
        )
