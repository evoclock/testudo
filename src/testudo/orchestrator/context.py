# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.orchestrator.context

Purpose: ``StepContext`` dataclass passed to every tool callable as its first
positional argument. Carries the resolved permissions, an optional audit log,
and the run/step identifiers. Tools that need to consult permissions or emit
audit events use this object; tools that do not can ignore it.

Inputs: constructor arguments built by the executor for each step.

Outputs: a frozen-ish dataclass passed to tools.

Assumptions: a single step runs synchronously; the executor builds one
``StepContext`` per step invocation.
"""

from __future__ import annotations

from dataclasses import dataclass

from testudo.audit import AuditLog
from testudo.permissions import Permissions


@dataclass(frozen=True, slots=True)
class StepContext:
    """Context available to a tool during step execution."""

    permissions: Permissions
    audit: AuditLog | None
    run_id: str
    workflow_name: str
    step_id: str
