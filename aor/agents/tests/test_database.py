from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest

from aor.agents.database import DatabaseAgent
from crypto_core import hash_payload


def _poi(plan):
    return SimpleNamespace(action_payload_hash=hash_payload(plan.payload).hex(), action_type=plan.action_type)


def test_database_agent_runs_only_registered_read_only_templates(tmp_path) -> None:
    database = tmp_path / "demo.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)")
        connection.execute("INSERT INTO items (name) VALUES ('one')")
        connection.commit()
    agent = DatabaseAgent({"demo": database})
    plan = agent.plan("list tables in demo", {"database": "demo", "template": "list_tables", "params": []})

    result = agent.execute(plan, _poi(plan))

    assert result.success is True
    assert {row["name"] for row in result.details["rows"]} == {"items"}


def test_database_agent_rejects_unregistered_database_and_arbitrary_sql(tmp_path) -> None:
    agent = DatabaseAgent()

    with pytest.raises(ValueError, match="database_not_registered"):
        agent.plan("query secret", {"database": "secret", "template": "list_tables", "params": []})
    try:
        agent.register_template("drop", "DROP TABLE items")
    except ValueError as exc:
        assert "read_only" in str(exc)
    else:
        raise AssertionError("arbitrary SQL template was accepted")


def test_database_agent_can_create_a_sandboxed_database(tmp_path) -> None:
    workspace = tmp_path / "databases"
    agent = DatabaseAgent(workspace_dir=workspace)
    plan = agent.plan("create a database named student")

    result = agent.execute(plan, _poi(plan))

    assert result.success is True
    assert result.details["database"] == "student"
    assert (workspace / "student.sqlite3").is_file()

    table_plan = agent.plan("[Conversation: create a database named student…] create table marks in student")
    table_result = agent.execute(table_plan, _poi(table_plan))

    assert table_result.success is True
    with sqlite3.connect(workspace / "student.sqlite3") as connection:
        columns = connection.execute("PRAGMA table_info(marks)").fetchall()
    assert columns[0][1] == "id"
