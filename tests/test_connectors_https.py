"""Tests for ``testudo.connectors.https``: scheme/content-type/size guards."""

from __future__ import annotations

import httpx
import pytest

from testudo.connectors.https import fetch_https


def _make_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fetch_https_returns_staged_input_on_200() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"hello",
            headers={"content-type": "text/plain"},
        )

    staged = fetch_https("https://example.com/x", client=_make_client(handler))
    assert staged.content == "hello"
    assert staged.format == "text"
    assert staged.metadata["status_code"] == 200
    assert staged.metadata["host"] == "example.com"


def test_fetch_https_accepts_octet_stream_for_drive_compat() -> None:
    """Regression: Drive serves shared files as octet-stream; must accept."""
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"# markdown body that drive served as octet-stream\n",
            headers={"content-type": "application/octet-stream"},
        )

    staged = fetch_https("https://example.com/x", client=_make_client(handler))
    assert "markdown body" in staged.content


def test_fetch_https_rejects_non_https_scheme() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        fetch_https("http://example.com/x")


def test_fetch_https_rejects_disallowed_content_type() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"binary",
            headers={"content-type": "application/octet-stream"},
        )

    with pytest.raises(ValueError, match="Disallowed content type"):
        fetch_https("https://example.com/x", client=_make_client(handler))


def test_fetch_https_rejects_oversize_response() -> None:
    big = b"x" * 5000

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=big, headers={"content-type": "text/plain"})

    with pytest.raises(ValueError, match="too large"):
        fetch_https(
            "https://example.com/big",
            client=_make_client(handler),
            max_bytes=100,
        )


def test_fetch_https_propagates_http_errors() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, content=b"oops")

    with pytest.raises(httpx.HTTPStatusError):
        fetch_https("https://example.com/x", client=_make_client(handler))


def test_fetch_https_infers_json_format_from_content_type() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"{}", headers={"content-type": "application/json"})

    staged = fetch_https("https://example.com/x", client=_make_client(handler))
    assert staged.format == "json"
