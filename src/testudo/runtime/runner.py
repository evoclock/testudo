"""
Module: testudo.runtime.runner

Purpose: high-level Runner that coordinates audit logging around a single
Docker-isolated workflow run. Allocates a per-run directory under
``runs_root``, opens an ``AuditLog``, emits ``workflow_start``, delegates to
``testudo.runtime.docker.invoke``, then emits ``workflow_end`` (or ``error``
on exception) before returning the ``RunResult``.

Inputs: ``workflow_path``, ``workflow_name``, ``isolation``, optional
``inputs_dir`` and ``timeout``.

Outputs: a ``RunResult``; persistent side effect is a ``runs/<run-id>/``
directory containing ``audit.jsonl`` plus whatever the workflow itself
wrote to ``/runs`` inside the container.

Assumptions: ``runs_root`` is host-side and writable. ``run_id`` is the
first 12 hex characters of a uuid4 so directory names are short but
sufficiently unique for v0.1.

Failure modes: ``docker.invoke`` exceptions (such as
``subprocess.TimeoutExpired``) are recorded as ``error`` audit events
before re-raising so the trail captures the failure.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from testudo.audit import AuditEvent, AuditLog
from testudo.runtime import docker
from testudo.runtime.isolation import IsolationProfile


class Runner:
    """Coordinate audit logging around a Docker-isolated workflow run."""

    def __init__(self, runs_root: Path) -> None:
        self.runs_root = runs_root
        runs_root.mkdir(parents=True, exist_ok=True)

    def run(
        self,
        *,
        workflow_path: Path,
        workflow_name: str,
        isolation: IsolationProfile,
        inputs_dir: Path | None = None,
        timeout: float | None = None,
    ) -> docker.RunResult:
        """Execute the workflow; emit audit events; return the ``RunResult``."""
        run_id = uuid.uuid4().hex[:12]
        run_dir = self.runs_root / run_id
        run_dir.mkdir()

        audit = AuditLog(run_dir / "audit.jsonl")
        audit.emit(
            AuditEvent(
                type="workflow_start",
                run_id=run_id,
                workflow=workflow_name,
                args={"isolation": isolation.model_dump()},
            )
        )

        try:
            result = docker.invoke(
                workflow_path=workflow_path,
                runs_dir=run_dir,
                isolation=isolation,
                inputs_dir=inputs_dir,
                timeout=timeout,
            )
        except Exception as exc:
            audit.emit(
                AuditEvent(
                    type="error",
                    run_id=run_id,
                    workflow=workflow_name,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
            raise

        audit.emit(
            AuditEvent(
                type="workflow_end",
                run_id=run_id,
                workflow=workflow_name,
                exit_status=result.exit_status,
                runtime_ms=result.runtime_ms,
            )
        )
        return result
