# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.server.rate_limit

Purpose: in-house token-bucket rate limiter for the FastAPI bridge. Per-token
quotas with monotonic-time refill. Built in-house (per the in-house-first
preference) rather than pulled from slowapi/python-limits; the bucket is
small enough that the dependency surface is not worth it.

Inputs: requests through ``RateLimitMiddleware``; the limiter consults
``TokenBucket`` keyed by the bearer token (or remote IP if anonymous).

Outputs: HTTP 429 with a ``Retry-After`` header when the bucket is empty.

Assumptions: single-process, single-host. v0.2 will swap the in-memory
bucket for a Redis-backed store if multi-process is needed; the
``RateLimiter`` interface is the seam.
"""

from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


@dataclass(slots=True)
class TokenBucket:
    """One token-bucket per client.

    ``capacity`` is the maximum burst size; ``refill_per_sec`` is the
    steady-state allowed rate. Both are floats so fractional refill works
    cleanly across short windows.
    """

    capacity: float
    refill_per_sec: float
    tokens: float
    last_refill: float

    @classmethod
    def new(cls, *, capacity: float, refill_per_sec: float) -> TokenBucket:
        now = time.monotonic()
        return cls(
            capacity=capacity,
            refill_per_sec=refill_per_sec,
            tokens=capacity,
            last_refill=now,
        )

    def take(self, cost: float = 1.0) -> tuple[bool, float]:
        """Try to take ``cost`` tokens. Return ``(allowed, wait_seconds)``.

        On success, ``wait_seconds`` is ``0``. On denial, it is the seconds
        the caller would need to wait before ``cost`` tokens are available.
        """
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
        self.last_refill = now

        if self.tokens >= cost:
            self.tokens -= cost
            return True, 0.0
        deficit = cost - self.tokens
        return False, deficit / self.refill_per_sec if self.refill_per_sec > 0 else float("inf")


class RateLimiter:
    """Per-key in-memory token-bucket store."""

    def __init__(self, *, capacity: float = 60.0, refill_per_sec: float = 1.0) -> None:
        self._capacity = capacity
        self._refill = refill_per_sec
        self._buckets: dict[str, TokenBucket] = defaultdict(self._new_bucket)

    def _new_bucket(self) -> TokenBucket:
        return TokenBucket.new(capacity=self._capacity, refill_per_sec=self._refill)

    def take(self, key: str, *, cost: float = 1.0) -> tuple[bool, float]:
        return self._buckets[key].take(cost)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that consults a :class:`RateLimiter`.

    Keying preference: the bearer token first (so distinct clients with
    distinct tokens have distinct buckets), falling back to ``X-Forwarded-For``
    or the client host if no token is present. Health-check paths are
    exempt; everything else costs one token per request.
    """

    EXEMPT_PATHS: frozenset[str] = frozenset({"/health", "/metrics"})

    def __init__(self, app: Any, *, limiter: RateLimiter | None = None) -> None:
        super().__init__(app)
        self._limiter = limiter or RateLimiter()

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        key = self._key_for(request)
        allowed, wait_seconds = self._limiter.take(key)
        if not allowed:
            if wait_seconds == float("inf"):
                retry_after = 86400
            else:
                retry_after = max(1, int(wait_seconds + 0.999))
            return Response(
                content=f'{{"detail": "rate limit exceeded; retry after {retry_after}s"}}',
                status_code=429,
                media_type="application/json",
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)

    @staticmethod
    def _key_for(request: Request) -> str:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            return f"token:{auth[7:]}"
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return f"ip:{forwarded.split(',', 1)[0].strip()}"
        if request.client:
            return f"ip:{request.client.host}"
        return "ip:unknown"
