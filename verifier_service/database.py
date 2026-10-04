"""SQLite persistence for AoR accounts, sessions, prompts, and artifacts."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

from .models import SignedEnvelope


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _password_digest(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)


class SQLiteDatabase:
    """Thread-safe, stdlib-only SQLite store used by the unified backend.

    The browser never receives password material or private signing keys. The
    session token is random and only its SHA-256 digest is stored in SQLite.
    """

    def __init__(self, path: str = ":memory:") -> None:
        self.path = path
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._connection:
            self._connection.executescript(
                """
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    role TEXT NOT NULL DEFAULT 'Member',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS prompt_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    prompt TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    action_id TEXT UNIQUE,
                    eml_path TEXT,
                    verification_json TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_prompt_records_user
                    ON prompt_records(user_id, created_at DESC);
                """
            )
        self._seed_demo_accounts()

    def _seed_demo_accounts(self) -> None:
        """Keep the credentials shown by the existing landing page usable."""
        row = self._connection.execute("SELECT 1 FROM users LIMIT 1").fetchone()
        if row is None:
            self.create_user("Alex Morgan", "alex@example.com", "Password123!")
            self.create_user("Jane Doe", "user@example.com", "password123")

    @staticmethod
    def _public_user(row: sqlite3.Row) -> dict[str, str]:
        return {
            "id": row["id"],
            "name": row["name"],
            "email": row["email"],
            "role": row["role"],
            "createdAt": row["created_at"],
        }

    def create_user(self, name: str, email: str, password: str) -> dict[str, str]:
        normalized_email = email.strip().lower()
        if not name.strip() or "@" not in normalized_email:
            raise ValueError("Name and a valid email address are required.")
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters long.")
        user_id = f"usr_{secrets.token_urlsafe(10)}"
        salt = os.urandom(16)
        digest = _password_digest(password, salt)
        now = _iso(_utc_now())
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    "INSERT INTO users (id,name,email,password_salt,password_hash,role,created_at) VALUES (?,?,?,?,?,?,?)",
                    (user_id, name.strip(), normalized_email, salt, digest, "Member", now),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError("An account with this email already exists.") from exc
        row = self._connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        assert row is not None
        return self._public_user(row)

    def authenticate(self, email: str, password: str) -> dict[str, str] | None:
        row = self._connection.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()
        if row is None or not hmac.compare_digest(_password_digest(password, row["password_salt"]), row["password_hash"]):
            return None
        return self._public_user(row)

    def user_by_id(self, user_id: str) -> dict[str, str] | None:
        row = self._connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return None if row is None else self._public_user(row)

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create_session(self, user_id: str, ttl_days: int = 7) -> str:
        token = secrets.token_urlsafe(32)
        now = _utc_now()
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO sessions (token_hash,user_id,created_at,expires_at) VALUES (?,?,?,?)",
                (self._token_hash(token), user_id, _iso(now), _iso(now + timedelta(days=ttl_days))),
            )
        return token

    def user_from_token(self, token: str | None) -> dict[str, str] | None:
        if not token:
            return None
        row = self._connection.execute(
            "SELECT users.*, sessions.expires_at AS session_expires FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash = ?",
            (self._token_hash(token),),
        ).fetchone()
        if row is None or datetime.fromisoformat(row["session_expires"]) <= _utc_now():
            return None
        return self._public_user(row)

    def revoke_session(self, token: str | None) -> None:
        if token:
            with self._lock, self._connection:
                self._connection.execute("DELETE FROM sessions WHERE token_hash = ?", (self._token_hash(token),))

    def save_prompt(
        self,
        envelope: SignedEnvelope,
        *,
        user_id: str,
        action_id: str | None = None,
        eml_path: str | None = None,
        verification: dict[str, Any] | None = None,
    ) -> int:
        verification_json = json.dumps(verification, separators=(",", ":")) if verification is not None else None
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                INSERT INTO prompt_records
                (user_id,session_id,prompt,envelope_json,action_id,eml_path,verification_json,created_at)
                VALUES (?,?,?,?,?,?,?,?)
                """,
                (user_id, envelope.session_id, envelope.prompt, envelope.model_dump_json(), action_id, eml_path, verification_json, _iso(_utc_now())),
            )
        return int(cursor.lastrowid)

    def update_prompt_action(self, action_id: str, eml_path: str, verification: dict[str, Any] | None = None) -> None:
        verification_json = json.dumps(verification, separators=(",", ":")) if verification is not None else None
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE prompt_records SET eml_path = ?, verification_json = COALESCE(?, verification_json) WHERE action_id = ?",
                (eml_path, verification_json, action_id),
            )

    def update_verification(self, action_id: str, verification: dict[str, Any]) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE prompt_records SET verification_json = ? WHERE action_id = ?",
                (json.dumps(verification, separators=(",", ":")), action_id),
            )

    def list_prompts(self, user_id: str, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            "SELECT * FROM prompt_records WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            result.append({
                "id": row["id"], "prompt": row["prompt"], "session_id": row["session_id"],
                "action_id": row["action_id"], "eml_path": row["eml_path"],
                "verification": json.loads(row["verification_json"]) if row["verification_json"] else None,
                "created_at": row["created_at"],
            })
        return result
