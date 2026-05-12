"""
Module: testudo.connectors.https

Purpose: fetch a resource via HTTPS GET and stage it as a ``StagedInput``.
Enforces an HTTPS-only scheme, a content-type allow-list, a byte-size cap,
and a request timeout.

Inputs: a URL (must be HTTPS); optional ``max_bytes`` (default 10 MiB),
``timeout`` (default 30s), ``allowed_content_types`` (default text/*,
application/json, application/yaml).

Outputs: a ``StagedInput`` with the response body and provenance metadata
(content-type, status code, host).

Assumptions: workflow's ``permissions.network.egress`` allow-list has been
checked by the caller before invoking this connector. The connector itself
does not consult permissions; it is the orchestrator's responsibility to gate
the network call at the policy layer.

Failure modes: ``ValueError`` for non-HTTPS URLs, disallowed content types,
or oversize responses; ``httpx.HTTPError`` subclasses for network failures
(propagated to the caller).
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from testudo.connectors.result import StagedInput

_DEFAULT_MAX_BYTES = 10 * 1024 * 1024
_DEFAULT_TIMEOUT = 30.0
_DEFAULT_ALLOWED_CONTENT_TYPES: tuple[str, ...] = (
    "text/",
    "application/json",
    "application/yaml",
    "application/x-yaml",
)


def fetch_https(
    url: str,
    *,
    max_bytes: int = _DEFAULT_MAX_BYTES,
    timeout: float = _DEFAULT_TIMEOUT,
    allowed_content_types: tuple[str, ...] = _DEFAULT_ALLOWED_CONTENT_TYPES,
    client: httpx.Client | None = None,
) -> StagedInput:
    """Fetch a URL via HTTPS GET and return a ``StagedInput``.

    The optional ``client`` parameter accepts a pre-built ``httpx.Client`` so
    tests can pass a ``MockTransport``-backed client without monkeypatching.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"Only HTTPS URLs are accepted: {url!r}")

    owned = client is None
    used = client if client is not None else httpx.Client(timeout=timeout)
    try:
        resp = used.get(url)
        resp.raise_for_status()
    finally:
        if owned:
            used.close()

    content_type = resp.headers.get("content-type", "").lower()
    if not any(content_type.startswith(t) for t in allowed_content_types):
        raise ValueError(
            f"Disallowed content type {content_type!r} (allowed: {list(allowed_content_types)})"
        )

    body = resp.content
    if len(body) > max_bytes:
        raise ValueError(f"Response too large: {len(body)} bytes (limit {max_bytes})")

    return StagedInput(
        content=resp.text,
        format=_format_from_content_type(content_type),
        source=url,
        size_bytes=len(body),
        metadata={
            "content_type": content_type,
            "status_code": resp.status_code,
            "host": parsed.hostname or "",
        },
    )


def _format_from_content_type(content_type: str) -> str:
    if content_type.startswith("application/json"):
        return "json"
    if content_type.startswith(("application/yaml", "application/x-yaml")):
        return "yaml"
    if content_type.startswith("text/markdown"):
        return "markdown"
    if content_type.startswith("text/csv"):
        return "csv"
    if content_type.startswith("text/html"):
        return "html"
    return "text"
