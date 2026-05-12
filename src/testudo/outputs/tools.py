"""
Module: testudo.outputs.tools

Purpose: register output channel functions as orchestrator tools so workflow
steps can reference them. Side effect of importing this module: every tool
below appears in the orchestrator's ``DEFAULT_REGISTRY``.
"""

from __future__ import annotations

from typing import Any

from testudo.orchestrator.context import StepContext
from testudo.orchestrator.registry import register_tool
from testudo.outputs.chat import write_chat
from testudo.outputs.dashboard import write_dashboard
from testudo.outputs.file import write_file
from testudo.outputs.ticket import create_ticket


@register_tool("outputs.file")
def file_tool(
    _ctx: StepContext,
    *,
    path: str,
    content: str,
) -> dict[str, Any]:
    """Write workflow output to a file in the writable layer."""
    return write_file(path, content)


@register_tool("outputs.chat")
def chat_tool(
    _ctx: StepContext,
    *,
    text: str,
    attachments: list[str] | None = None,
) -> dict[str, Any]:
    """Build a chat-inline response payload for the UI."""
    return write_chat(text, attachments=attachments)


@register_tool("outputs.dashboard")
def dashboard_tool(
    _ctx: StepContext,
    *,
    component: str,
    props: dict[str, Any],
) -> dict[str, Any]:
    """Emit a dashboard component spec for the renderer."""
    return write_dashboard(component, props)


@register_tool("outputs.ticket")
def ticket_tool(
    _ctx: StepContext,
    *,
    webhook_url: str,
    title: str,
    body: str,
    labels: list[str] | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Create a ticket via webhook POST."""
    return create_ticket(webhook_url, title=title, body=body, labels=labels, timeout=timeout)
