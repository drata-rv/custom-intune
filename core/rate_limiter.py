"""Async token-bucket rate limiter for Drata API calls.

The Drata Custom MDM endpoint enforces 500 requests/minute per IP. We target
420 req/min (7 req/sec) to maintain a ~15% safety margin. This headroom
absorbs retry bursts without tripping the hard limit.

Usage::

    bucket = TokenBucket(rate=7.0, per=1.0)

    async def push_device(payload):
        await bucket.acquire()       # blocks until a token is available
        await post_to_drata(payload)
"""

from __future__ import annotations

import asyncio
import time


class TokenBucket:
    """Async token-bucket rate limiter.

    Tokens refill at ``rate`` per ``per`` seconds. ``acquire()`` blocks
    (non-busy -- uses ``asyncio.sleep``) until a token is available.

    Thread-safety within an event loop is provided by ``asyncio.Lock``.
    """

    def __init__(self, rate: float, per: float = 1.0) -> None:
        """Initialize the bucket.

        Args:
            rate: Number of tokens to grant per ``per`` seconds.
                  E.g., ``rate=7, per=1.0`` -> 7 tokens/second.
            per:  Time window in seconds over which ``rate`` tokens refill.
        """
        if rate <= 0 or per <= 0:
            raise ValueError(f"rate ({rate}) and per ({per}) must be positive")

        self._rate: float = rate
        self._per: float = per
        self._tokens: float = rate          # start full
        self._last_refill: float = time.monotonic()
        self._lock: asyncio.Lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available, then consume it.

        Uses ``asyncio.sleep`` instead of busy-waiting so the event loop
        can service other coroutines while we wait for a refill.
        """
        async with self._lock:
            while True:
                self._refill()

                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return

                deficit = 1.0 - self._tokens
                wait_seconds = deficit * (self._per / self._rate)
                await asyncio.sleep(wait_seconds)

    def _refill(self) -> None:
        """Add tokens based on elapsed time since the last refill."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._last_refill = now
        self._tokens = min(self._rate, self._tokens + elapsed * (self._rate / self._per))
