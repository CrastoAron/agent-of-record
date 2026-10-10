from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from aor.agents.file import FileAgent
from crypto_core import hash_payload


def _poi(plan):
    return SimpleNamespace(
        action_payload_hash=hash_payload(plan.payload).hex(),
        action_type=plan.action_type,
    )


def test_file_agent_rejects_path_traversal(tmp_path) -> None:
    agent = FileAgent(tmp_path)
    plan = agent.plan("read file ../outside.txt", {"action_type": "file.read", "path": "../outside.txt"})

    result = agent.execute(plan, _poi(plan))

    assert result.success is False
    assert result.details["error"] == "path_outside_workspace"


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_file_agent_rejects_symlink_escape(tmp_path) -> None:
    outside = tmp_path.parent / "aor-outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(outside)
    agent = FileAgent(tmp_path)
    plan = agent.plan("read file link.txt", {"action_type": "file.read", "path": "link.txt"})

    result = agent.execute(plan, _poi(plan))

    assert result.success is False
    assert result.details["error"] == "path_outside_workspace"


def test_delete_requires_confirmation(tmp_path) -> None:
    target = tmp_path / "delete.txt"
    target.write_text("remove me", encoding="utf-8")
    agent = FileAgent(tmp_path)
    plan = agent.plan("delete file delete.txt", {"action_type": "file.delete", "path": "delete.txt"})

    blocked = agent.execute(plan, _poi(plan))
    allowed_plan = plan.model_copy(update={"confirmed": True})
    executed = agent.execute(allowed_plan, _poi(allowed_plan))

    assert plan.requires_confirmation is True
    assert blocked.details["error"] == "confirmation_required"
    assert executed.success is True
    assert executed.observed_effect["before_hash"]
    assert not target.exists()


def test_update_uses_unified_diff_and_records_hashes(tmp_path) -> None:
    target = tmp_path / "note.txt"
    target.write_text("one\ntwo\n", encoding="utf-8")
    patch = "--- note.txt\n+++ note.txt\n@@ -1,2 +1,2 @@\n one\n-two\n+changed\n"
    agent = FileAgent(tmp_path)
    plan = agent.plan("update file note.txt", {"action_type": "file.update", "path": "note.txt", "patch": patch})

    result = agent.execute(plan, _poi(plan))

    assert result.success is True
    assert target.read_text(encoding="utf-8") == "one\nchanged\n"
    assert result.observed_effect["before_hash"] != result.observed_effect["after_hash"]
    assert result.observed_effect["backup_ref"]
