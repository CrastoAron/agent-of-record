"""SQLite agent with sandboxed database creation and approved read queries."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from crypto_core import hash_payload

from .base import ActionPlan, ActionResult, Agent


class DatabaseAgentError(ValueError):
    """Raised when a database request violates the database policy."""


class DatabaseAgent(Agent):
    """Manage/query SQLite databases through explicit safe operations."""

    agent_type = "database"
    capabilities = ("db.query", "db.create", "db.create_table")
    DEFAULT_TEMPLATES = {
        "list_tables": "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
        "prompt_history": (
            "SELECT id, user_id, prompt, action_id, created_at "
            "FROM prompt_records WHERE user_id = ? ORDER BY created_at DESC LIMIT ?"
        ),
    }

    def __init__(
        self,
        databases: Mapping[str, str | Path] | None = None,
        *,
        workspace_dir: str | Path | None = None,
        agent_id: str = "database-agent",
    ) -> None:
        super().__init__(agent_id=agent_id)
        self._databases = {name: Path(path).resolve() for name, path in (databases or {}).items()}
        self._workspace_dir = Path(workspace_dir).resolve() if workspace_dir is not None else None
        self._templates = dict(self.DEFAULT_TEMPLATES)

    def register_database(self, name: str, path: str | Path) -> None:
        if not name or not name.strip():
            raise DatabaseAgentError("database_name_required")
        resolved = Path(path).resolve()
        if not resolved.is_file():
            raise DatabaseAgentError("registered_database_not_found")
        self._databases[name] = resolved

    def register_template(self, name: str, sql: str) -> None:
        """Register a reviewable SELECT/CTE template, never arbitrary SQL."""
        if not name or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name):
            raise DatabaseAgentError("invalid_template_name")
        normalized = sql.strip().lower()
        if ";" in sql or not normalized.startswith(("select ", "with ")):
            raise DatabaseAgentError("only_single_read_only_select_templates_are_allowed")
        self._templates[name] = sql.strip()

    def can_handle(self, request: str) -> bool:
        return bool(request and re.search(r"\b(database|sqlite|query|records|table|sql)\b", request, re.IGNORECASE))

    def plan(self, request: str, context: Mapping[str, Any] | None = None) -> ActionPlan:
        if not request or not request.strip():
            raise DatabaseAgentError("database_request_empty")
        active_request = self._active_request(request)
        values = dict(context or {})
        action_type = values.get("action_type") or self._action_type_from_request(active_request)
        if action_type == "db.create":
            name = values.get("name") or self._database_name_from_request(active_request)
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,62}", name):
                raise DatabaseAgentError("database_name_required")
            if self._workspace_dir is None:
                raise DatabaseAgentError("database_workspace_not_configured")
            path = (self._workspace_dir / f"{name}.sqlite3").resolve()
            if path.parent != self._workspace_dir:
                raise DatabaseAgentError("database_path_outside_workspace")
            return ActionPlan(
                agent_type=self.agent_type,
                agent_id=self.agent_id,
                action_type="db.create",
                payload={"database": name, "path": str(path)},
                policy_decision="allow",
            )
        if action_type == "db.create_table":
            table = values.get("table") or self._table_name_from_request(active_request)
            database = values.get("database") or self._database_name_from_request(active_request)
            if not isinstance(table, str) or not self._valid_identifier(table):
                raise DatabaseAgentError("table_name_required")
            if not isinstance(database, str) or database not in self._databases:
                raise DatabaseAgentError("database_not_registered")
            columns = values.get("columns") or [{"name": "id", "type": "INTEGER", "primary_key": True}]
            self._validate_columns(columns)
            return ActionPlan(
                agent_type=self.agent_type,
                agent_id=self.agent_id,
                action_type="db.create_table",
                payload={"database": database, "table": table, "columns": columns},
                policy_decision="allow",
            )
        database = values.get("database") or self._database_from_request(active_request)
        template = values.get("template") or self._template_from_request(active_request)
        params = values.get("params", [])
        if database not in self._databases:
            raise DatabaseAgentError("database_not_registered")
        if template not in self._templates:
            raise DatabaseAgentError("query_template_not_approved")
        if not isinstance(params, list):
            raise DatabaseAgentError("query_params_must_be_a_list")
        return ActionPlan(
            agent_type=self.agent_type,
            agent_id=self.agent_id,
            action_type="db.query",
            payload={"database": database, "template": template, "params": params},
            policy_decision="allow",
        )

    def execute(self, plan: ActionPlan, poi: Any) -> ActionResult:
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
        allowed_poi_types = (
            {None, "db.create"}
            if plan.action_type == "db.create"
            else {None, "db", "db.query", "db.create_table"}
        )
        if getattr(poi, "action_type", None) not in allowed_poi_types:
            return self._failure("action_type_mismatch")
        try:
            if plan.action_type == "db.create":
                name = self._required_string(plan.payload, "database")
                path = self._safe_create_path(self._required_string(plan.payload, "path"))
                if path.exists():
                    return self._failure("database_already_exists")
                path.parent.mkdir(parents=True, exist_ok=True)
                with sqlite3.connect(path):
                    pass
                self._databases[name] = path
                return ActionResult(
                    success=True,
                    artifact_ref=name,
                    details={"database": name, "path": str(path), "created": True},
                    observed_effect={"database": name, "path": str(path), "created": True},
                )
            if plan.action_type == "db.create_table":
                database = self._required_string(plan.payload, "database")
                table = self._required_string(plan.payload, "table")
                path = self._databases[database]
                columns = plan.payload.get("columns")
                self._validate_columns(columns)
                if not self._valid_identifier(table):
                    raise DatabaseAgentError("invalid_table_name")
                definitions = ", ".join(self._column_sql(column) for column in columns)
                with sqlite3.connect(path) as connection:
                    existing = connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                        (table,),
                    ).fetchone()
                    if existing is not None:
                        return self._failure("table_already_exists")
                    connection.execute(f'CREATE TABLE "{table}" ({definitions})')
                return ActionResult(
                    success=True,
                    artifact_ref=f"{database}:{table}",
                    details={"database": database, "table": table, "columns": columns, "created": True},
                    observed_effect={"database": database, "table": table, "created": True},
                )
            database = self._required_string(plan.payload, "database")
            template = self._required_string(plan.payload, "template")
            params = plan.payload.get("params", [])
            path = self._databases[database]
            sql = self._templates[template]
            with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
                connection.row_factory = sqlite3.Row
                rows = [dict(row) for row in connection.execute(sql, params).fetchall()]
            query_hash = hash_payload({"template": template, "params": params}).hex()
            return ActionResult(
                success=True,
                artifact_ref=database,
                details={"database": database, "template": template, "rows": rows},
                observed_effect={"row_count": len(rows), "query_hash": query_hash},
            )
        except (KeyError, OSError, sqlite3.Error, DatabaseAgentError, TypeError, ValueError) as exc:
            return self._failure(str(exc))

    @staticmethod
    def _required_string(payload: Mapping[str, Any], key: str) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            raise DatabaseAgentError(f"{key}_required")
        return value

    @staticmethod
    def _failure(detail: str) -> ActionResult:
        return ActionResult(success=False, details={"error": detail})

    def _database_from_request(self, request: str) -> str | None:
        for name in self._databases:
            if re.search(rf"\b{re.escape(name)}\b", request):
                return name
        return next(iter(self._databases), None)

    def _template_from_request(self, request: str) -> str:
        lowered = request.lower()
        if "table" in lowered:
            return "list_tables"
        if "history" in lowered or "prompt" in lowered or "record" in lowered:
            return "prompt_history"
        return "list_tables"

    @staticmethod
    def _active_request(request: str) -> str:
        """Ignore the UI's signed conversation-context prefix for planning."""
        return request.rsplit("]", 1)[-1].strip() if "]" in request else request.strip()

    @staticmethod
    def _valid_identifier(value: str) -> bool:
        return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,62}", value))

    @classmethod
    def _table_name_from_request(cls, request: str) -> str | None:
        match = re.search(r"\btable\s+([A-Za-z][A-Za-z0-9_]*)", request, re.IGNORECASE)
        return match.group(1) if match else None

    @classmethod
    def _validate_columns(cls, columns: Any) -> None:
        if not isinstance(columns, list) or not columns:
            raise DatabaseAgentError("columns_required")
        allowed_types = {"INTEGER", "REAL", "TEXT", "BLOB", "NUMERIC"}
        for column in columns:
            if not isinstance(column, dict) or not cls._valid_identifier(str(column.get("name", ""))):
                raise DatabaseAgentError("invalid_column_name")
            if str(column.get("type", "")).upper() not in allowed_types:
                raise DatabaseAgentError("invalid_column_type")

    @staticmethod
    def _column_sql(column: Mapping[str, Any]) -> str:
        name = str(column["name"])
        column_type = str(column["type"]).upper()
        primary_key = " PRIMARY KEY" if column.get("primary_key") else ""
        return f'"{name}" {column_type}{primary_key}'

    @staticmethod
    def _action_type_from_request(request: str) -> str:
        if re.search(r"\bcreate\s+(?:a\s+)?table\b", request, re.IGNORECASE):
            return "db.create_table"
        return "db.create" if re.search(r"\bcreate\s+(?:a\s+)?database\b", request, re.IGNORECASE) else "db.query"

    @staticmethod
    def _database_name_from_request(request: str) -> str | None:
        match = re.search(
            r"\bdatabase\s+(?:named|called)\s+[`\"']?([A-Za-z][A-Za-z0-9_-]{0,62})",
            request,
            re.IGNORECASE,
        )
        if match:
            return match.group(1)
        match = re.search(r"\bcreate\s+(?:a\s+)?database\s+[`\"']?([A-Za-z][A-Za-z0-9_-]{0,62})", request, re.IGNORECASE)
        if match:
            return match.group(1)
        match = re.search(r"\bin\s+[`\"']?([A-Za-z][A-Za-z0-9_-]{0,62})", request, re.IGNORECASE)
        return match.group(1) if match else None

    def _safe_create_path(self, path: str) -> Path:
        if self._workspace_dir is None:
            raise DatabaseAgentError("database_workspace_not_configured")
        resolved = Path(path).resolve()
        if resolved.parent != self._workspace_dir or resolved.suffix != ".sqlite3":
            raise DatabaseAgentError("database_path_outside_workspace")
        return resolved
