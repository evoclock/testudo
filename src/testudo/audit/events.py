"""
Module: testudo.audit.events

Purpose: Pydantic models for the structured events emitted by Testudo's audit
log. One model per event, frozen so accidental mutation after construction
fails fast. Events carry an event type, a run identifier, and a timestamp so
downstream tooling can stitch a run's records back together.

Inputs: constructor arguments per event type.

Outputs: ``AuditEvent`` instances ready for serialisation as one JSON line each
via ``model_dump_json``.

Assumptions: events are append-only and write-through; the orchestrator does
not consider a step complete until its audit record has been flushed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

EventType = Literal[
    "workflow_start",
    "workflow_end",
    "step_start",
    "step_end",
    "permission_decision",
    "error",
]


class AuditEvent(BaseModel):
    """One row in the audit log.

    Optional fields are populated depending on the event type; the ``type``
    field disambiguates downstream consumers.
    """

    model_config = ConfigDict(frozen=True)

    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    type: EventType
    run_id: str
    workflow: str
    pid: int | None = None
    step_id: str | None = None
    args: dict[str, object] | None = None
    decision: dict[str, object] | None = None
    error: str | None = None
    runtime_ms: int | None = None
    exit_status: int | None = None
    stdout: str | None = None
    stderr: str | None = None
