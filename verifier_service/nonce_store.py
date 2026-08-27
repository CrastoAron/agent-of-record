"""Bounded, in-memory nonce replay protection for the verifier service."""

from __future__ import annotations

import time
from collections.abc import Callable


class NonceStore:
    """Track nonces until a bounded TTL has elapsed."""

    def __init__(self, ttl_seconds: int = 300, clock: Callable[[], float] = time.monotonic) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._seen: dict[str, float] = {}

    def _sweep_expired(self) -> None:
        now = self._clock()
        self._seen = {
            nonce: seen_at
            for nonce, seen_at in self._seen.items()
            if now - seen_at <= self._ttl_seconds
        }

    def has_seen(self, nonce: str) -> bool:
        """Return whether a nonce has been observed within the retention window."""
        self._sweep_expired()
        return nonce in self._seen

    def mark_seen(self, nonce: str) -> None:
        """Record a nonce at the current monotonic time."""
        self._sweep_expired()
        self._seen[nonce] = self._clock()
