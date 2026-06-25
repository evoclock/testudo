# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Testudo model-adapter package.

Purpose: LLM provider adapters that the orchestrator can call as workflow
steps. Every model adapter routes its response through
:func:`testudo.sanitisers.output.sanitise_output` before returning, so the
output side of the security pipeline applies to every model call without
per-workflow wiring.

Inputs: tool kwargs from a workflow's ``with:`` block.

Outputs: a JSON-serialisable dict with ``decision``, ``content``,
``findings``, ``model``, ``raw_length``, ``sanitised_length``.

Side effect: importing this package triggers registration of the
adapter tools in the orchestrator's ``DEFAULT_REGISTRY``.
"""

from testudo.models import tools  # noqa: F401  - registers adapter tools
from testudo.models.ollama import ollama_chat

__all__ = ["ollama_chat"]
