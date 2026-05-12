"""Testudo audit package.

Purpose: structured audit logging. Writes one JSONL record per workflow invocation
(and one per step) capturing PID, parameters, stdio, runtime, exit status, and any
permission decisions taken during execution.

Inputs: events from ``runtime/``, ``orchestrator/``, ``permissions/``, and the
in-container subsystems.

Outputs: a JSONL audit log file (default ``runs/<run-id>/audit.jsonl``) and
optionally a streaming sink (host-side aggregator, future).

Assumptions: audit is append-only and write-through; the runtime considers a step
complete only after its audit record has been flushed.
"""
