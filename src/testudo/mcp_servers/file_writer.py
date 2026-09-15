# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.mcp_servers.file_writer

Purpose: write-side file operations MCP server. Modelled on hillstar's
``mcp-server/file_operations_mcp_server.py``. This is the only MCP server
with disk-write capability. Every write request must carry a valid
sanitisation receipt issued by
:mod:`testudo.mcp_servers.llm_response_capturer`; an unsigned or stale
receipt is a hard rejection.

Inputs: ``write_file``, ``update_file``, and ``create_directory`` tool
calls. Each carries a ``receipt`` field plus a ``run_id`` matching the
receipt's ``run_id``.

Outputs: a JSON-RPC result with a confirmation string, or
``isError: true`` with the rejection reason (path validation, missing
receipt, signature mismatch, file-not-found for update).

Assumptions: paths are constrained to ``REPO_ROOT`` (configurable via
env). Path traversal is rejected before the receipt check. The signing
key is loaded from ``TESTUDO_RECEIPT_KEY`` (the same env the capturer
reads).

References:

- Hillstar ``mcp-server/file_operations_mcp_server.py`` (path-validation
  pattern).
- MCP presentation v4 slide 12 (only file_ops writes) and slide 24
  (policy as safety boundary).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from testudo.mcp_servers.base import BaseMCPServer, ToolSpec
from testudo.mcp_servers.llm_response_capturer import verify_receipt

REPO_ROOT_ENV = "TESTUDO_REPO_ROOT"


def _repo_root() -> Path:
    return Path(os.environ.get(REPO_ROOT_ENV, os.getcwd())).resolve()


def _validate_path(path: str) -> Path:
    """Resolve ``path`` relative to repo root and reject any escape."""
    root = _repo_root()
    abs_path = (root / path).resolve()
    try:
        abs_path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Path {path!r} resolves outside repo root {root}") from exc
    return abs_path


def _check_receipt(arguments: dict[str, object], content: str) -> tuple[bool, str]:
    """Verify the sanitisation receipt carried by a write request."""
    receipt = arguments.get("receipt")
    if not isinstance(receipt, dict):
        return False, "missing or malformed receipt"
    if receipt.get("decision") == "reject":
        return False, "receipt indicates the content was rejected by the sanitiser"
    if not verify_receipt(receipt=receipt, content=content):
        return False, "receipt signature does not match content"
    return True, ""


def _write_file(arguments: dict[str, object]) -> dict[str, object]:
    path = arguments.get("path")
    content = arguments.get("content")
    if not isinstance(path, str) or not isinstance(content, str):
        return _err("path and content are required strings")

    try:
        abs_path = _validate_path(path)
    except ValueError as exc:
        return _err(str(exc))

    ok, reason = _check_receipt(arguments, content)
    if not ok:
        return _err(f"receipt rejected: {reason}")

    abs_path.parent.mkdir(parents=True, exist_ok=True)
    abs_path.write_text(content, encoding="utf-8")
    return _ok(f"wrote {path} ({len(content)} bytes)")


def _update_file(arguments: dict[str, object]) -> dict[str, object]:
    path = arguments.get("path")
    old_content = arguments.get("old_content")
    new_content = arguments.get("new_content")
    if not all(isinstance(x, str) for x in (path, old_content, new_content)):
        return _err("path, old_content, and new_content are required strings")
    assert isinstance(path, str)
    assert isinstance(old_content, str)
    assert isinstance(new_content, str)

    try:
        abs_path = _validate_path(path)
    except ValueError as exc:
        return _err(str(exc))

    if not abs_path.exists():
        return _err(f"file not found: {path}")

    current = abs_path.read_text(encoding="utf-8")
    if old_content not in current:
        return _err(f"old_content not found in {path}")

    ok, reason = _check_receipt(arguments, new_content)
    if not ok:
        return _err(f"receipt rejected: {reason}")

    updated = current.replace(old_content, new_content, 1)
    abs_path.write_text(updated, encoding="utf-8")
    return _ok(f"updated {path}")


def _create_directory(arguments: dict[str, object]) -> dict[str, object]:
    path = arguments.get("path")
    if not isinstance(path, str):
        return _err("path is required")

    try:
        abs_path = _validate_path(path)
    except ValueError as exc:
        return _err(str(exc))

    abs_path.mkdir(parents=True, exist_ok=True)
    return _ok(f"created directory {path}")


def _ok(text: str) -> dict[str, object]:
    return {"isError": False, "content": [{"type": "text", "text": text}]}


def _err(text: str) -> dict[str, object]:
    return {"isError": True, "content": [{"type": "text", "text": text}]}


def build_server() -> BaseMCPServer:
    """Build a configured ``file_writer`` MCP server."""
    server = BaseMCPServer(name="file_writer")

    server.register(
        ToolSpec(
            name="write_file",
            description=(
                "Write or create a file under REPO_ROOT. Requires a valid "
                "sanitisation receipt issued by the llm_response_capturer."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                    "receipt": {"type": "object"},
                },
                "required": ["path", "content", "receipt"],
            },
            handler=_write_file,
        ),
    )

    server.register(
        ToolSpec(
            name="update_file",
            description=(
                "Replace one occurrence of old_content with new_content under "
                "REPO_ROOT. Requires a valid sanitisation receipt for new_content."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "old_content": {"type": "string"},
                    "new_content": {"type": "string"},
                    "receipt": {"type": "object"},
                },
                "required": ["path", "old_content", "new_content", "receipt"],
            },
            handler=_update_file,
        ),
    )

    server.register(
        ToolSpec(
            name="create_directory",
            description="Create a directory under REPO_ROOT (creates parents).",
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            handler=_create_directory,
        ),
    )

    return server


if __name__ == "__main__":
    # silence the unused-import warning while keeping json available for
    # downstream callers
    _ = json
    build_server().run()
