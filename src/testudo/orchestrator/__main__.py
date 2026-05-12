"""
Script: testudo orchestrator (in-container entry point)

Path: src/testudo/orchestrator/__main__.py

Purpose: in-container entry point invoked by the Docker image's ENTRYPOINT.
Loads the workflow at ``argv[1]`` (default ``/workflow.json``), resolves
its permissions, runs it via the synchronous ``Executor``, and prints a
per-step summary to stderr.

Inputs: positional argument ``workflow_path`` (default ``/workflow.json``);
optional ``--inputs path.json`` for a JSON file of workflow inputs.

Outputs: per-step status to stderr; exit 0 if all steps succeeded, 1 if
any step errored.

Assumptions: the workflow file is bind-mounted into the container at
``/workflow.json`` by the host-side runtime; per-run audit log is written
to ``/runs/audit.jsonl``.

Parameters: ``workflow_path`` (str), ``--inputs`` (path).

Failure modes: missing or unreadable workflow file (exit 2 with stderr);
schema validation failure (exit 2); any unexpected exception (exit 3).

Author: Julen Gamboa

Created: 2026-05-12

Last Edited: 2026-05-12 by Julen Gamboa
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from testudo.audit import AuditLog
from testudo.orchestrator import (
    DEFAULT_REGISTRY,
    Executor,
    load_workflow,
    resolve_permissions,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="testudo.orchestrator")
    parser.add_argument(
        "workflow_path",
        nargs="?",
        default="/workflow.json",
        help="Path to workflow.json (default /workflow.json).",
    )
    parser.add_argument(
        "--inputs",
        type=str,
        default=None,
        help="Path to a JSON file of workflow inputs.",
    )
    parser.add_argument(
        "--audit",
        type=str,
        default="/runs/audit.jsonl",
        help="Path for the audit JSONL (default /runs/audit.jsonl).",
    )
    parser.add_argument(
        "--run-id",
        type=str,
        default="local",
        help="Run identifier propagated into audit events.",
    )
    args = parser.parse_args(argv)

    workflow_path = Path(args.workflow_path)
    if not workflow_path.is_file():
        print(
            f"[testudo.orchestrator] workflow not found: {workflow_path}",
            file=sys.stderr,
        )
        return 2

    try:
        workflow = load_workflow(workflow_path)
    except Exception as exc:
        print(
            f"[testudo.orchestrator] failed to load workflow: {exc}",
            file=sys.stderr,
        )
        return 2

    inputs: dict[str, object] = {}
    if args.inputs is not None:
        try:
            inputs = json.loads(Path(args.inputs).read_text(encoding="utf-8"))
        except Exception as exc:
            print(
                f"[testudo.orchestrator] failed to load inputs: {exc}",
                file=sys.stderr,
            )
            return 2

    permissions = resolve_permissions(workflow)

    audit_path = Path(args.audit)
    audit = AuditLog(audit_path)

    executor = Executor(registry=DEFAULT_REGISTRY, audit=audit)
    results = executor.run(workflow, inputs, permissions, run_id=args.run_id)

    failed = 0
    for step_id, result in results.items():
        if result.error is not None:
            print(f"[FAIL] {step_id}: {result.error}", file=sys.stderr)
            failed += 1
        elif result.skipped:
            print(f"[SKIP] {step_id}", file=sys.stderr)
        else:
            print(f"[OK]   {step_id}", file=sys.stderr)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
