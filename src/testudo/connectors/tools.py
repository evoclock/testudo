"""
Module: testudo.connectors.tools

Purpose: register connector functions as orchestrator tools so workflow steps
can reference them by name. Side effect of importing this module: every tool
below appears in the orchestrator's ``DEFAULT_REGISTRY``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from testudo.connectors.drive import fetch_drive
from testudo.connectors.https import fetch_https
from testudo.connectors.local import fetch_local
from testudo.orchestrator.context import StepContext
from testudo.orchestrator.registry import register_tool


@register_tool("connectors.local_file")
def local_file_tool(
    _ctx: StepContext,
    *,
    path: str,
    max_bytes: int = 10 * 1024 * 1024,
) -> dict[str, Any]:
    """Read a local file and return a StagedInput dict."""
    return fetch_local(Path(path), max_bytes=max_bytes).to_dict()


@register_tool("connectors.https_get")
def https_get_tool(
    _ctx: StepContext,
    *,
    url: str,
    max_bytes: int = 10 * 1024 * 1024,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Fetch an HTTPS URL and return a StagedInput dict."""
    return fetch_https(url, max_bytes=max_bytes, timeout=timeout).to_dict()


@register_tool("connectors.google_drive")
def google_drive_tool(
    _ctx: StepContext,
    *,
    file_id: str,
    credentials: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Fetch a Google Drive file (v0.2 placeholder)."""
    return fetch_drive(file_id, credentials=credentials).to_dict()
