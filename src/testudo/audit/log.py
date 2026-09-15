# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.audit.log

Purpose: append-only JSONL writer for ``AuditEvent`` records. One file per
workflow run; the parent directory is created on construction so the caller
does not have to.

Inputs: a target path for the audit log; ``AuditEvent`` instances passed to
``emit``.

Outputs: a JSONL file on disk, one event per line; ``read`` returns the parsed
events for tests and the ``testudo inspect`` CLI subcommand.

Assumptions: v0.1 is single-process; concurrent writes are not guarded. v0.2
will add a per-file lock if multi-process emission becomes a real path.
"""

from __future__ import annotations

from pathlib import Path

from testudo.audit.events import AuditEvent


class AuditLog:
    """Append-only JSONL audit log."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: AuditEvent) -> None:
        """Append one event as a single JSON line."""
        with self.path.open("a", encoding="utf-8") as f:
            f.write(event.model_dump_json())
            f.write("\n")

    def read(self) -> list[AuditEvent]:
        """Read all events from the log; intended for tests and ``testudo inspect``."""
        if not self.path.exists():
            return []
        events: list[AuditEvent] = []
        with self.path.open(encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                events.append(AuditEvent.model_validate_json(line))
        return events
