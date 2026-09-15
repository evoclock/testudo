# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Testudo outputs package.

Purpose: output channel adapters. v0.1 ships file (writable rollback layer),
chat (structured response for the Electron UI), dashboard (component spec),
and ticket (webhook POST).

Inputs: an output object from the workflow's final step.

Outputs: persisted artefacts on disk (file channel) plus JSON-serialisable
payloads the host-side renderer consumes via the FastAPI bridge.

Side effect: importing this package registers ``outputs.file``,
``outputs.chat``, ``outputs.dashboard``, and ``outputs.ticket`` in the
orchestrator's ``DEFAULT_REGISTRY``.
"""

from testudo.outputs import tools  # noqa: F401  - registers output tools
from testudo.outputs.chat import write_chat
from testudo.outputs.dashboard import write_dashboard
from testudo.outputs.file import write_file
from testudo.outputs.ticket import create_ticket

__all__ = [
    "create_ticket",
    "write_chat",
    "write_dashboard",
    "write_file",
]
