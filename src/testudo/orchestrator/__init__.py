# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Testudo orchestrator package.

Purpose: lightweight in-container workflow runner. Reads Hillstar's
``workflow.json`` format (with Testudo-specific ``permissions:`` and
``isolation:`` extensions), executes steps in topological dependency order,
emits audit events around each invocation, and resolves ``${...}``
references in step ``with:`` arguments.

Inputs: a ``Workflow`` (parsed by ``loader.load_workflow``), a dict of
inputs, a ``Permissions`` model, and optionally an ``AuditLog``.

Outputs: a dict mapping step IDs to ``StepResult``.

Assumptions: the executor is synchronous in v0.1; async + parallel batches
land in v0.2. Tools register themselves in the ``DEFAULT_REGISTRY`` at
import time.
"""

# Importing tools registers the v0.1 baseline (noop) into DEFAULT_REGISTRY.
from testudo.orchestrator import tools  # noqa: F401
from testudo.orchestrator.context import StepContext
from testudo.orchestrator.executor import Executor, StepResult, WorkflowError
from testudo.orchestrator.loader import (
    load_workflow,
    resolve_isolation,
    resolve_permissions,
)
from testudo.orchestrator.registry import (
    DEFAULT_REGISTRY,
    ToolRegistry,
    register_tool,
)
from testudo.orchestrator.workflow import Step, Workflow, WorkflowInput

__all__ = [
    "DEFAULT_REGISTRY",
    "Executor",
    "Step",
    "StepContext",
    "StepResult",
    "ToolRegistry",
    "Workflow",
    "WorkflowError",
    "WorkflowInput",
    "load_workflow",
    "register_tool",
    "resolve_isolation",
    "resolve_permissions",
]
