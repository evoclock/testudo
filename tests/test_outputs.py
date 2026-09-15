# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for ``testudo.outputs``: file, chat, dashboard, ticket channels."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from testudo.outputs.chat import write_chat
from testudo.outputs.dashboard import write_dashboard
from testudo.outputs.file import write_file
from testudo.outputs.ticket import create_ticket

# ----------------------------------------------------------------------------
# File
# ----------------------------------------------------------------------------


def test_write_file_creates_file_and_returns_metadata(tmp_path: Path) -> None:
    target = tmp_path / "out" / "result.md"
    payload = write_file(target, "hello")
    assert target.exists()
    assert target.read_text(encoding="utf-8") == "hello"
    assert payload["channel"] == "file"
    assert payload["destination"] == str(target.resolve())
    assert payload["size_bytes"] == 5


def test_write_file_overwrites_existing(tmp_path: Path) -> None:
    target = tmp_path / "result.md"
    target.write_text("old", encoding="utf-8")
    payload = write_file(target, "new")
    assert target.read_text(encoding="utf-8") == "new"
    assert payload["size_bytes"] == 3


# ----------------------------------------------------------------------------
# Chat
# ----------------------------------------------------------------------------


def test_write_chat_returns_canonical_shape() -> None:
    payload = write_chat("hello world")
    assert payload == {"channel": "chat", "text": "hello world", "attachments": []}


def test_write_chat_preserves_attachments() -> None:
    payload = write_chat("see file", attachments=["/runs/result.md"])
    assert payload["attachments"] == ["/runs/result.md"]


# ----------------------------------------------------------------------------
# Dashboard
# ----------------------------------------------------------------------------


def test_write_dashboard_emits_component_spec() -> None:
    payload = write_dashboard("line_chart", {"x": [1, 2], "y": [3, 4]})
    assert payload["channel"] == "dashboard"
    assert payload["component"] == "line_chart"
    assert payload["props"] == {"x": [1, 2], "y": [3, 4]}


def test_write_dashboard_copies_props() -> None:
    props = {"x": 1}
    payload = write_dashboard("text", props)
    props["x"] = 99
    assert payload["props"]["x"] == 1


# ----------------------------------------------------------------------------
# Ticket
# ----------------------------------------------------------------------------


def test_create_ticket_posts_to_webhook_and_returns_metadata() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["url"] = str(request.url)
        captured["body"] = request.content
        return httpx.Response(
            201,
            json={"id": "T-42"},
            headers={
                "location": "https://tickets.example.com/T-42",
                "content-type": "application/json",
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    payload = create_ticket(
        "https://hook.example.com/tickets",
        title="Demo",
        body="Body text",
        labels=["demo"],
        client=client,
    )
    assert payload["channel"] == "ticket"
    assert payload["ticket_id"] == "T-42"
    assert payload["url"] == "https://tickets.example.com/T-42"
    assert payload["status_code"] == 201
    assert captured["method"] == "POST"


def test_create_ticket_propagates_http_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(httpx.HTTPStatusError):
        create_ticket(
            "https://hook.example.com/tickets",
            title="x",
            body="x",
            client=client,
        )


def test_create_ticket_handles_non_json_response() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, content=b"queued")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    payload = create_ticket(
        "https://hook.example.com/tickets",
        title="x",
        body="x",
        client=client,
    )
    assert payload["ticket_id"] is None
    assert payload["status_code"] == 202
