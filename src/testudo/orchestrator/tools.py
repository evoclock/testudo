# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.orchestrator.tools

Purpose: built-in tools that ship with the orchestrator. v0.1 ships a single
``noop`` tool useful for diagnostics and tests; real tools (connectors,
sanitisers, data adapters, outputs) land in Chunks 4 and 5 and register
themselves into the same default registry by importing this package.

Inputs: tool kwargs from the workflow's ``with:`` block.

Outputs: a dict (the canonical step-output shape).

Assumptions: imported by ``testudo.orchestrator.__init__`` so registration
happens automatically when callers ``import testudo.orchestrator``.
"""

from __future__ import annotations

from typing import Any

from testudo.orchestrator.context import StepContext
from testudo.orchestrator.registry import register_tool


@register_tool("noop")
def noop(_ctx: StepContext, **kwargs: Any) -> dict[str, Any]:
    """Echo kwargs back to the caller. Useful for tests and diagnostics."""
    return {"echoed": dict(kwargs)}
