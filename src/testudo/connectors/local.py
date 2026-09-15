# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.connectors.local

Purpose: read a local file and stage it as a ``StagedInput`` for downstream
workflow steps. Enforces a configurable byte-size cap and infers a format hint
from the file extension.

Inputs: a path to a local file; optional ``max_bytes`` (default 10 MiB).

Outputs: a ``StagedInput`` with the text content and provenance metadata
(``mtime`` for change-detection use cases).

Assumptions: v0.1 reads text only (utf-8); binary files raise on decode failure.
The host-side runtime mounts allowed read prefixes into the container at
``/inputs``; this connector trusts the file is already accessible from inside
the workflow's filesystem permission scope (callers may invoke
``require_filesystem_read`` from ``testudo.permissions`` before calling).

Failure modes: ``FileNotFoundError`` if the path does not exist or is not a
regular file; ``ValueError`` if the file exceeds ``max_bytes``;
``UnicodeDecodeError`` if the bytes are not valid utf-8.
"""

from __future__ import annotations

from pathlib import Path

from testudo.connectors.result import StagedInput

_DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10 MiB

_FORMAT_BY_EXT: dict[str, str] = {
    "json": "json",
    "csv": "csv",
    "yaml": "yaml",
    "yml": "yaml",
    "md": "markdown",
    "markdown": "markdown",
    "txt": "text",
    "html": "html",
    "xml": "xml",
}


def fetch_local(
    path: Path | str,
    *,
    max_bytes: int = _DEFAULT_MAX_BYTES,
) -> StagedInput:
    """Read a local file and return a ``StagedInput``."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Not a file: {p}")

    stat = p.stat()
    if stat.st_size > max_bytes:
        raise ValueError(f"File too large: {stat.st_size} bytes (limit {max_bytes})")

    content = p.read_text(encoding="utf-8")
    return StagedInput(
        content=content,
        format=_infer_format(p),
        source=str(p),
        size_bytes=stat.st_size,
        metadata={"mtime": stat.st_mtime},
    )


def _infer_format(path: Path) -> str:
    return _FORMAT_BY_EXT.get(path.suffix.lstrip(".").lower(), "text")
