"""In-memory, configurable periodic Context Ledger root anchoring."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from ledger_core import Ledger, build_merkle_tree

from .models import AnchorRecord
from .tsa_client import TSAClient, TSARequestError


class AnchorStore:
    """Append-only in-memory anchor records, indexed by ledger root."""

    def __init__(self) -> None:
        self._records: list[AnchorRecord] = []

    def add(self, record: AnchorRecord) -> AnchorRecord:
        self._records.append(record)
        return record

    def for_root(self, ledger_root: bytes) -> list[AnchorRecord]:
        return [record for record in self._records if record.ledger_root == ledger_root]

    def latest_anchored(self, ledger_root: bytes) -> AnchorRecord | None:
        return next((record for record in reversed(self.for_root(ledger_root)) if record.status == "anchored"), None)

    def all_records(self) -> list[AnchorRecord]:
        return list(self._records)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def anchor_current_root(
    ledger: Ledger, *, client: TSAClient | None = None, store: AnchorStore | None = None
) -> AnchorRecord:
    """Anchor the current root once; return the prior record if it is unchanged."""
    store = store or AnchorStore()
    try:
        root = build_merkle_tree(ledger.all_entries()).root()
    except ValueError as exc:
        return store.add(AnchorRecord(b"", None, None, _now(), "failed", str(exc)))
    existing = store.latest_anchored(root)
    if existing is not None:
        return existing
    try:
        token = (client or TSAClient()).request_timestamp(root)
    except TSARequestError as exc:
        return store.add(AnchorRecord(root, None, None, _now(), "failed", str(exc)))
    return store.add(AnchorRecord(root, token.response_bytes, token.gen_time, _now(), "anchored"))


class AnchorScheduler:
    """Simple periodic scheduler; production deployments replace this with a job queue."""

    def __init__(
        self, ledger: Ledger, client: TSAClient | None = None, store: AnchorStore | None = None,
        interval_seconds: float = 300,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self.ledger = ledger
        self.client = client or TSAClient()
        self.store = store or AnchorStore()
        self.interval_seconds = interval_seconds

    def run_once(self) -> AnchorRecord:
        return anchor_current_root(self.ledger, client=self.client, store=self.store)

    async def run_periodically(self, stop_event: asyncio.Event) -> None:
        """Anchor changed roots every interval until the caller asks this task to stop."""
        while not stop_event.is_set():
            self.run_once()
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=self.interval_seconds)
            except TimeoutError:
                continue
