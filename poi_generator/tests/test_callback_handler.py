from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger_core import Ledger, build_merkle_tree
from poi_generator import (
    MissingVerifiedSessionContext,
    PoICallbackHandler,
    VerifiedSessionContext,
    verify_poi_signature,
)


def _session_context() -> VerifiedSessionContext:
    ledger = Ledger()
    ledger.append("system_prompt", {"text": "Only send approved email."})
    ledger.append("user_prompt", {"text": "Send Bob an update."})
    return VerifiedSessionContext(
        session_id="verified-session-1",
        user_prompt="Send Bob an update.",
        system_prompt="Only send approved email.",
        ledger=ledger,
        model_id="demo-model",
    )


def test_tool_start_produces_poi_before_appending_tool_call() -> None:
    context = _session_context()
    private_key = Ed25519PrivateKey.generate()
    expected_root = build_merkle_tree(context.ledger.all_entries()).root().hex()
    handler = PoICallbackHandler({context.session_id: context}, private_key)
    run_id = uuid4()

    handler.on_tool_start(
        {"name": "send_email"},
        '{"to":"bob@example.com","subject":"Update"}',
        run_id=run_id,
        metadata={"session_id": context.session_id},
    )
    poi = handler.get_poi(run_id)

    assert poi.context_root == expected_root
    assert verify_poi_signature(poi, private_key.public_key())
    assert context.ledger.all_entries()[-1].entry_type == "tool_call"


def test_tool_start_blocks_when_verified_context_is_missing() -> None:
    handler = PoICallbackHandler(agent_private_key=Ed25519PrivateKey.generate())

    with pytest.raises(MissingVerifiedSessionContext):
        handler.on_tool_start(
            {"name": "send_email"},
            '{"to":"bob@example.com"}',
            run_id=uuid4(),
            metadata={"session_id": "missing"},
        )
