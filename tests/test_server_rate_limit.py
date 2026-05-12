"""Tests for the in-house token-bucket rate limiter."""

from __future__ import annotations

import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from testudo.server.rate_limit import (
    RateLimiter,
    RateLimitMiddleware,
    TokenBucket,
)


def test_token_bucket_allows_initial_burst() -> None:
    bucket = TokenBucket.new(capacity=5.0, refill_per_sec=1.0)
    for _ in range(5):
        ok, _ = bucket.take()
        assert ok


def test_token_bucket_denies_when_empty() -> None:
    bucket = TokenBucket.new(capacity=2.0, refill_per_sec=1.0)
    bucket.take()
    bucket.take()
    ok, wait = bucket.take()
    assert not ok
    assert wait > 0


def test_token_bucket_refills_over_time() -> None:
    bucket = TokenBucket.new(capacity=2.0, refill_per_sec=10.0)
    bucket.take()
    bucket.take()
    time.sleep(0.15)
    ok, _ = bucket.take()
    assert ok


def test_rate_limiter_per_key_isolation() -> None:
    limiter = RateLimiter(capacity=1.0, refill_per_sec=0.0)
    ok_a, _ = limiter.take("alpha")
    ok_b, _ = limiter.take("beta")
    assert ok_a and ok_b
    ok_a2, _ = limiter.take("alpha")
    assert not ok_a2


def _build_app(limiter: RateLimiter) -> FastAPI:
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, limiter=limiter)

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.get("/ping")
    def ping():
        return {"pong": True}

    return app


def test_middleware_exempts_health_path() -> None:
    limiter = RateLimiter(capacity=0.0, refill_per_sec=0.0)
    client = TestClient(_build_app(limiter))
    assert client.get("/health").status_code == 200


def test_middleware_returns_429_when_bucket_empty() -> None:
    limiter = RateLimiter(capacity=1.0, refill_per_sec=0.0)
    client = TestClient(_build_app(limiter))
    assert client.get("/ping").status_code == 200
    response = client.get("/ping")
    assert response.status_code == 429
    assert "Retry-After" in response.headers


def test_middleware_keys_by_bearer_token() -> None:
    limiter = RateLimiter(capacity=1.0, refill_per_sec=0.0)
    client = TestClient(_build_app(limiter))
    headers_a = {"Authorization": "Bearer alpha"}
    headers_b = {"Authorization": "Bearer beta"}
    assert client.get("/ping", headers=headers_a).status_code == 200
    # different token, different bucket
    assert client.get("/ping", headers=headers_b).status_code == 200
    # same token a, bucket exhausted
    assert client.get("/ping", headers=headers_a).status_code == 429
