"""
Module: testudo.outputs.chat

Purpose: structure a chat-inline response for the Electron UI to render.
Returns a JSON-serialisable dict the renderer consumes via the FastAPI
bridge (Chunk 6) or the host-side CLI when running outside the UI.

Inputs: a text message; an optional list of attachment URIs (typically
file paths returned by ``outputs.file``).

Outputs: a JSON-serialisable dict (channel, text, attachments).
"""

from __future__ import annotations

from typing import Any


def write_chat(text: str, attachments: list[str] | None = None) -> dict[str, Any]:
    """Build a structured chat-response payload."""
    return {
        "channel": "chat",
        "text": text,
        "attachments": list(attachments) if attachments else [],
    }
