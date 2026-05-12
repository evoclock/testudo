"""Testudo audit package.

Purpose: structured audit logging. Writes one JSONL record per event (workflow
start/end, step start/end, permission decision, error) so a run can be
reconstructed from the log alone.

Inputs: ``AuditEvent`` instances from the orchestrator, runtime, and
in-container subsystems.

Outputs: a JSONL audit log file at ``runs/<run-id>/audit.jsonl`` by default.

Assumptions: append-only and write-through; the runtime considers a step
complete only after its audit record has been flushed.
"""

from testudo.audit.events import AuditEvent, EventType
from testudo.audit.log import AuditLog

__all__ = ["AuditEvent", "AuditLog", "EventType"]
