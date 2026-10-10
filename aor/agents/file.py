"""Sandboxed file agent with explicit, auditable filesystem effects."""

from __future__ import annotations

import difflib
import hashlib
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from crypto_core import hash_payload, hash_sha3_256

from .base import ActionPlan, ActionResult, Agent


class FileAgentError(ValueError):
    """Raised when a file request is invalid or outside the configured sandbox."""


class FileAgent(Agent):
    """Plan and execute file operations below one configured workspace."""

    agent_type = "file"
    capabilities = (
        "file.read",
        "file.create",
        "file.update",
        "file.rename",
        "file.delete",
    )

    def __init__(
        self,
        workspace_dir: str | Path,
        backup_dir: str | Path | None = None,
        *,
        agent_id: str = "file-agent",
    ) -> None:
        super().__init__(agent_id=agent_id)
        self.workspace_dir = Path(workspace_dir).resolve()
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir = Path(backup_dir).resolve() if backup_dir else self.workspace_dir / ".aor_file_backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def can_handle(self, request: str) -> bool:
        if not request or not request.strip():
            return False
        return bool(
            re.search(
                r"\b(file|folder|directory|read|create|write|edit|update|rename|delete)\b",
                request,
                re.IGNORECASE,
            )
        )

    def plan(self, request: str, context: Mapping[str, Any] | None = None) -> ActionPlan:
        """Create a typed plan from structured context or simple demo syntax."""
        if not request or not request.strip():
            raise FileAgentError("file_request_empty")
        values = dict(context or {})
        action_type = values.get("action_type") or self._action_type_from_request(request)
        if action_type not in self.capabilities:
            raise FileAgentError("file_action_type_required")

        path = values.get("path") or self._extract_path(request)
        if not isinstance(path, str) or not path.strip():
            raise FileAgentError("file_path_required")
        payload: dict[str, Any] = {"path": path}
        if action_type == "file.create":
            payload["content"] = str(values.get("content", self._content_after_marker(request)))
        elif action_type == "file.update":
            patch = values.get("patch") or self._content_after_marker(request, marker="patch")
            if not patch:
                raise FileAgentError("file_update_patch_required")
            payload["patch"] = str(patch)
        elif action_type == "file.rename":
            destination = values.get("destination") or self._rename_destination(request)
            if not isinstance(destination, str) or not destination.strip():
                raise FileAgentError("file_destination_required")
            payload["destination"] = destination

        requires_confirmation = action_type == "file.delete"
        if action_type == "file.rename":
            requires_confirmation = self._resolve_path(destination).exists()
        return ActionPlan(
            agent_type=self.agent_type,
            agent_id=self.agent_id,
            action_type=action_type,
            payload=payload,
            requires_confirmation=requires_confirmation,
            policy_decision="allow",
        )

    def execute(self, plan: ActionPlan, poi: Any) -> ActionResult:
        """Execute only a PoI-bound plan inside the configured workspace."""
        if plan.agent_type != self.agent_type:
            return self._failure("agent_type_mismatch")
        if plan.agent_id is not None and plan.agent_id != self.agent_id:
            return self._failure("agent_id_mismatch")
        if plan.action_type not in self.capabilities:
            return self._failure("unsupported_action_type")
        if plan.policy_decision != "allow":
            return self._failure("policy_decision_rejected")
        if hash_payload(plan.payload).hex() != getattr(poi, "action_payload_hash", None):
            return self._failure("action_payload_hash_mismatch")
        if getattr(poi, "action_type", None) not in (None, plan.action_type):
            return self._failure("action_type_mismatch")

        try:
            return self._execute_checked(plan)
        except FileAgentError as exc:
            return self._failure(str(exc))

    def _execute_checked(self, plan: ActionPlan) -> ActionResult:
        action_type = plan.action_type
        path = self._resolve_path(self._required_string(plan.payload, "path"))
        if action_type == "file.read":
            if not path.is_file():
                raise FileAgentError("file_not_found")
            content = path.read_text(encoding="utf-8")
            digest = _digest(content.encode("utf-8"))
            return ActionResult(
                success=True,
                artifact_ref=str(path),
                details={"path": str(path), "content": content},
                observed_effect={"path": str(path), "before_hash": digest, "after_hash": digest},
            )

        if action_type == "file.create":
            if path.exists():
                raise FileAgentError("file_already_exists")
            content = self._required_string(plan.payload, "content")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="")
            after_hash = _digest(content.encode("utf-8"))
            backup_ref = self._write_change_record(plan, path, None, content)
            return self._change_result(path, None, after_hash, backup_ref)

        if action_type == "file.update":
            if not path.is_file():
                raise FileAgentError("file_not_found")
            before = path.read_text(encoding="utf-8")
            patch = self._required_string(plan.payload, "patch")
            after = _apply_unified_diff(before, patch)
            before_hash = _digest(before.encode("utf-8"))
            after_hash = _digest(after.encode("utf-8"))
            backup_ref = self._write_change_record(plan, path, before, after)
            path.write_text(after, encoding="utf-8", newline="")
            return self._change_result(path, before_hash, after_hash, backup_ref)

        if action_type == "file.delete":
            if not plan.confirmed:
                raise FileAgentError("confirmation_required")
            if not path.is_file():
                raise FileAgentError("file_not_found")
            before = path.read_text(encoding="utf-8")
            before_hash = _digest(before.encode("utf-8"))
            backup_ref = self._write_change_record(plan, path, before, None)
            path.unlink()
            return self._change_result(path, before_hash, None, backup_ref)

        if action_type == "file.rename":
            destination = self._resolve_path(self._required_string(plan.payload, "destination"))
            if destination.exists() and not plan.confirmed:
                raise FileAgentError("confirmation_required")
            if not path.is_file():
                raise FileAgentError("file_not_found")
            if destination.exists() and destination.is_dir():
                raise FileAgentError("destination_is_directory")
            before_hash = _digest(path.read_bytes())
            destination.parent.mkdir(parents=True, exist_ok=True)
            backup_ref = self._write_change_record(plan, path, str(path), str(destination))
            path.replace(destination)
            return ActionResult(
                success=True,
                artifact_ref=str(destination),
                details={"path": str(path), "destination": str(destination)},
                observed_effect={
                    "path": str(path),
                    "destination": str(destination),
                    "before_hash": before_hash,
                    "after_hash": _digest(destination.read_bytes()),
                    "backup_ref": backup_ref,
                },
            )

        raise FileAgentError("unsupported_action_type")

    def _resolve_path(self, relative_path: str) -> Path:
        candidate = (self.workspace_dir / relative_path).resolve()
        try:
            inside = os.path.commonpath((str(self.workspace_dir), str(candidate))) == str(self.workspace_dir)
        except ValueError:
            inside = False
        if not inside:
            raise FileAgentError("path_outside_workspace")
        return candidate

    def _write_change_record(self, plan: ActionPlan, path: Path, before: Any, after: Any) -> str:
        material = f"{plan.action_type}:{path}:{hashlib.sha256(repr((before, after)).encode()).hexdigest()}"
        record_path = self.backup_dir / f"{hashlib.sha256(material.encode()).hexdigest()}.diff"
        if isinstance(before, str) and isinstance(after, str):
            record = "".join(
                difflib.unified_diff(
                    before.splitlines(keepends=True),
                    after.splitlines(keepends=True),
                    fromfile=str(path),
                    tofile=str(path),
                )
            )
        else:
            record = f"action={plan.action_type}\npath={path}\nbefore={before!r}\nafter={after!r}\n"
        record_path.write_text(record, encoding="utf-8")
        return str(record_path)

    @staticmethod
    def _change_result(path: Path, before_hash: str | None, after_hash: str | None, backup_ref: str) -> ActionResult:
        return ActionResult(
            success=True,
            artifact_ref=str(path),
            details={"path": str(path)},
            observed_effect={
                "path": str(path),
                "before_hash": before_hash,
                "after_hash": after_hash,
                "backup_ref": backup_ref,
            },
        )

    @staticmethod
    def _failure(detail: str) -> ActionResult:
        return ActionResult(success=False, details={"error": detail})

    @staticmethod
    def _required_string(payload: Mapping[str, Any], key: str) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            raise FileAgentError(f"{key}_required")
        return value

    @staticmethod
    def _action_type_from_request(request: str) -> str | None:
        lowered = request.lower()
        for verb, action in (
            ("read", "file.read"),
            ("create", "file.create"),
            ("write", "file.create"),
            ("update", "file.update"),
            ("edit", "file.update"),
            ("rename", "file.rename"),
            ("delete", "file.delete"),
        ):
            if re.search(rf"\b{verb}\b", lowered):
                return action
        return None

    @staticmethod
    def _extract_path(request: str) -> str | None:
        match = re.search(r"(?:file|path)\s*[=:]?\s*[`\"']?([^`\"'\s]+)", request, re.IGNORECASE)
        if match:
            return match.group(1)
        fallback = re.search(r"\b(?:write|create|edit|update|rename|delete)\s+[`\"']?([^`\"'\s]+)", request, re.IGNORECASE)
        return fallback.group(1) if fallback else None

    @staticmethod
    def _content_after_marker(request: str, marker: str = "content") -> str:
        match = re.search(rf"\b{marker}\s*[:=]\s*(.*)$", request, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ""

    @staticmethod
    def _rename_destination(request: str) -> str | None:
        match = re.search(r"\bto\s+[`\"']?([^`\"'\s]+)", request, re.IGNORECASE)
        return match.group(1) if match else None


def _digest(value: bytes) -> str:
    return hash_sha3_256(value).hex()


def _apply_unified_diff(original: str, patch: str) -> str:
    """Apply a standard unified diff and reject context or range mismatches."""
    original_lines = original.splitlines(keepends=True)
    patch_lines = patch.splitlines(keepends=True)
    hunks = [index for index, line in enumerate(patch_lines) if line.startswith("@@ ")]
    if not hunks:
        raise FileAgentError("invalid_unified_diff")

    output: list[str] = []
    source_index = 0
    for hunk_position, start in enumerate(hunks):
        header = patch_lines[start]
        match = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", header)
        if not match:
            raise FileAgentError("invalid_unified_diff_header")
        old_start = int(match.group(1)) - 1
        output.extend(original_lines[source_index:old_start])
        source_index = old_start
        end = hunks[hunk_position + 1] if hunk_position + 1 < len(hunks) else len(patch_lines)
        for line in patch_lines[start + 1 : end]:
            if not line or line[0] not in " +-\\":
                raise FileAgentError("invalid_unified_diff_line")
            marker, content = line[0], line[1:]
            if marker == " ":
                if source_index >= len(original_lines) or original_lines[source_index] != content:
                    raise FileAgentError("patch_context_mismatch")
                output.append(content)
                source_index += 1
            elif marker == "-":
                if source_index >= len(original_lines) or original_lines[source_index] != content:
                    raise FileAgentError("patch_delete_mismatch")
                source_index += 1
            elif marker == "+":
                output.append(content)
            elif marker == "\\":
                continue
    output.extend(original_lines[source_index:])
    return "".join(output)
