"""SQLite persistence adapter for key records; replaceable with Postgres/KMS metadata."""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone

from .models import AgentKeyRecord


def _timestamp_to_storage(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(timezone.utc).isoformat()


def _timestamp_from_storage(value: str | None) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value).astimezone(timezone.utc)


class SQLiteKeyStorage:
    """Small synchronous SQLite CRUD adapter for public key records only."""

    def __init__(self, database_path: str = ":memory:") -> None:
        self._connection = sqlite3.connect(database_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_keys (
                    pubkey_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    public_key_bytes BLOB NOT NULL,
                    algorithm TEXT NOT NULL,
                    valid_from TEXT NOT NULL,
                    valid_until TEXT,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
                """
            )

    @staticmethod
    def _record_from_row(row: sqlite3.Row) -> AgentKeyRecord:
        return AgentKeyRecord(
            agent_id=row["agent_id"],
            pubkey_id=row["pubkey_id"],
            public_key_bytes=row["public_key_bytes"],
            algorithm=row["algorithm"],
            valid_from=_timestamp_from_storage(row["valid_from"]),
            valid_until=_timestamp_from_storage(row["valid_until"]),
            revoked=bool(row["revoked"]),
            created_at=_timestamp_from_storage(row["created_at"]),
        )

    def insert_key(self, record: AgentKeyRecord) -> None:
        """Persist a new immutable key record, rejecting duplicate key IDs."""
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    """
                    INSERT INTO agent_keys
                    (pubkey_id, agent_id, public_key_bytes, algorithm, valid_from,
                     valid_until, revoked, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.pubkey_id,
                        record.agent_id,
                        record.public_key_bytes,
                        record.algorithm,
                        _timestamp_to_storage(record.valid_from),
                        _timestamp_to_storage(record.valid_until),
                        int(record.revoked),
                        _timestamp_to_storage(record.created_at),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"pubkey_id already registered: {record.pubkey_id}") from exc

    def get_key_by_id(self, pubkey_id: str) -> AgentKeyRecord | None:
        """Retrieve a key record regardless of validity or revocation state."""
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM agent_keys WHERE pubkey_id = ?", (pubkey_id,)
            ).fetchone()
        return None if row is None else self._record_from_row(row)

    def get_keys_by_agent(self, agent_id: str) -> list[AgentKeyRecord]:
        """Retrieve all records for an agent, newest first."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM agent_keys WHERE agent_id = ? ORDER BY created_at DESC", (agent_id,)
            ).fetchall()
        return [self._record_from_row(row) for row in rows]

    def all_keys(self) -> list[AgentKeyRecord]:
        """Retrieve all stored records for JWK Set publication."""
        with self._lock:
            rows = self._connection.execute("SELECT * FROM agent_keys ORDER BY created_at DESC").fetchall()
        return [self._record_from_row(row) for row in rows]

    def revoke_key(self, pubkey_id: str) -> bool:
        """Mark a key revoked and return whether a record existed."""
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "UPDATE agent_keys SET revoked = 1 WHERE pubkey_id = ?", (pubkey_id,)
            )
        return cursor.rowcount > 0
