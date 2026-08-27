"""An in-memory append-only hash chain for AoR context entries."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from crypto_core.hashing import hash_payload


@dataclass
class LedgerEntry:
    """One context item and its place in the ledger hash chain.

    ``content`` deliberately remains a dictionary so forensic tests can mutate
    stored data directly to model an attacker bypassing the Ledger API. Normal
    callers should treat returned entries as immutable records.
    """

    entry_id: int
    entry_type: str
    content: dict[str, Any]
    timestamp: str
    prev_hash: bytes
    leaf_hash: bytes


class Ledger:
    """Append-only, in-memory context ledger.

    The public interface intentionally exposes only append and read operations.
    The ``_entries`` list gives a future persistence adapter a single, clear
    storage boundary to replace.
    """

    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []

    @staticmethod
    def _leaf_material(content: dict[str, Any], prev_hash: bytes) -> dict[str, Any]:
        """Return the canonical payload whose hash commits a ledger leaf."""
        return {"content": content, "prev_hash": prev_hash.hex()}

    @classmethod
    def _compute_leaf_hash(cls, content: dict[str, Any], prev_hash: bytes) -> bytes:
        """Commit content and its predecessor using the Stage 1 hash helper."""
        return hash_payload(cls._leaf_material(content, prev_hash))

    def append(self, entry_type: str, content: dict[str, Any]) -> LedgerEntry:
        """Append a context entry and return its newly created ledger record."""
        if not isinstance(entry_type, str) or not entry_type:
            raise ValueError("entry_type must be a non-empty string")
        if not isinstance(content, dict):
            raise TypeError("content must be a dictionary")

        prev_hash = self._entries[-1].leaf_hash if self._entries else b""
        stored_content = deepcopy(content)
        entry = LedgerEntry(
            entry_id=len(self._entries) + 1,
            entry_type=entry_type,
            content=stored_content,
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            prev_hash=prev_hash,
            leaf_hash=self._compute_leaf_hash(stored_content, prev_hash),
        )
        self._entries.append(entry)
        return entry

    def get_entry(self, entry_id: int) -> LedgerEntry:
        """Return the entry with *entry_id*, or raise ``KeyError`` if absent."""
        if not isinstance(entry_id, int) or entry_id < 1:
            raise KeyError(entry_id)
        try:
            return self._entries[entry_id - 1]
        except IndexError as exc:
            raise KeyError(entry_id) from exc

    def all_entries(self) -> list[LedgerEntry]:
        """Return entries in append order as a new list of record references."""
        return list(self._entries)

    def first_invalid_entry_id(self) -> int | None:
        """Return the first broken entry ID, or ``None`` when the chain is valid."""
        expected_prev_hash = b""
        for entry in self._entries:
            expected_leaf_hash = self._compute_leaf_hash(entry.content, expected_prev_hash)
            if entry.prev_hash != expected_prev_hash or entry.leaf_hash != expected_leaf_hash:
                return entry.entry_id
            expected_prev_hash = entry.leaf_hash
        return None

    def verify_chain(self) -> bool:
        """Return ``True`` only when every entry still matches the hash chain."""
        return self.first_invalid_entry_id() is None
