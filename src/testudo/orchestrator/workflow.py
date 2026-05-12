"""
Module: testudo.orchestrator.workflow

Purpose: Pydantic models for a Testudo workflow. The schema is compatible with
Hillstar's ``workflow.json`` format and adds Testudo-specific ``permissions:``
and ``isolation:`` blocks. ``extra="ignore"`` on the workflow and step models so
Hillstar workflows with additional fields parse without modification.

Inputs: a parsed dict (from JSON or YAML) matching the workflow schema.

Outputs: a frozen ``Workflow`` instance.

Assumptions: every step has a unique ``id``; ``needs:`` references resolve to
other step IDs in the same workflow; ``with:`` argument values may contain
``${inputs.x}`` or ``${steps.y.z}`` references resolved at execution time by
``testudo.orchestrator.executor``.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class WorkflowInput(BaseModel):
    """Declaration of one input the workflow accepts."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: str
    format: str | None = None
    required: bool = True
    default: Any = None


class Step(BaseModel):
    """One step in a workflow.

    ``with_`` is the ``with:`` block (renamed because ``with`` is a reserved
    word in Python); the populate-by-name + alias config lets workflow files
    use ``with:`` while the model exposes ``with_`` to Python.
    """

    model_config = ConfigDict(frozen=True, extra="ignore", populate_by_name=True)

    id: str
    uses: str
    needs: tuple[str, ...] = ()
    with_: dict[str, Any] = Field(default_factory=dict, alias="with")
    when: str | None = None


class Workflow(BaseModel):
    """A Testudo workflow loaded from ``workflow.json``."""

    model_config = ConfigDict(frozen=True, extra="ignore", populate_by_name=True)

    name: str
    description: str | None = None
    inputs: dict[str, WorkflowInput] = Field(default_factory=dict)
    steps: tuple[Step, ...]
    permissions: dict[str, Any] | None = None
    isolation: dict[str, Any] | None = None
