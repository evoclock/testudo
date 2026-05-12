"""Testudo permissions package.

Purpose: declarative per-workflow permission model and the runtime enforcement that
goes with it. Deny-by-default for filesystem reads/writes, network egress, and
process spawning. Permissions are declared in the workflow's ``permissions:`` block
(YAML or JSON) and surfaced to the audit log on every decision.

Inputs: a permissions block from the workflow specification.

Outputs: a ``Permissions`` object that ``runtime/`` and the in-container subsystems
consult before any privileged operation; permission decisions are emitted to
``audit/`` in real time.

Assumptions: permissions are static for the duration of a workflow run; dynamic
permission elevation is out of scope for v0.x.
"""
