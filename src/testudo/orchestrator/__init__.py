"""Testudo orchestrator package.

Purpose: lightweight in-container workflow runner. Reads Hillstar's ``workflow.json``
format (with Testudo-specific ``permissions:`` and ``isolation:`` extensions),
executes steps in dependency order, and supports branches and simple async-parallel
fan-out.

Inputs: a parsed ``Workflow`` plus inputs (file paths, structured arguments).

Outputs: a ``RunResult`` carrying per-step outputs, the final outputs, and the audit
record.

Assumptions: workflow steps are pure functions over their declared inputs; side
effects are routed through the permissioned ``connectors/``, ``data/``, and
``outputs/`` packages so the runtime can audit them.
"""
