"""
Module: testudo.outputs.file

Purpose: file writer for workflow outputs. Writes content to the workflow's
writable layer (``/runs`` inside the container, the host-side run directory
when running outside Docker) and returns the destination path plus byte
count.

Inputs: a target path; the content to write.

Outputs: a JSON-serialisable dict (channel, destination, size_bytes).

Assumptions: the host-side runtime's filesystem-write permissions allow
writes to the target path; the orchestrator already gated the call.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def write_file(path: Path | str, content: str) -> dict[str, Any]:
    """Write ``content`` to ``path`` (creating parents as needed)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return {
        "channel": "file",
        "destination": str(p.resolve()),
        "size_bytes": p.stat().st_size,
    }
