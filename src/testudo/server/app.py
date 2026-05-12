"""
Module: testudo.server.app

Purpose: FastAPI bridge for the Electron UI and any HTTP client. Endpoints:

- ``GET /health`` — liveness probe (no auth).
- ``GET /workflows`` — list workflows under the configured directory.
- ``POST /runs`` — execute a workflow synchronously; return the per-step
  results plus the audit log path.
- ``GET /runs/{run_id}`` — fetch a previously-completed run's results.

Inputs: HTTP requests; constructor wiring (runs_root, workflows_root,
optional bearer token).

Outputs: a configured FastAPI app object.

Assumptions: v0.1 runs synchronously inside the request handler; v0.2 will
add a background-task queue for long-running workflows. The token is
generated at startup and printed to stderr by ``testudo serve``; the
Electron main process reads it from there.
"""

from __future__ import annotations

import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, status

from testudo import __version__, _loaded  # noqa: F401  - registers built-in tools
from testudo.audit import AuditLog
from testudo.orchestrator import (
    Executor,
    load_workflow,
    resolve_permissions,
)
from testudo.server.auth import TokenAuth, generate_token
from testudo.server.models import (
    HealthResponse,
    RunRequest,
    RunResponse,
    StepResultPayload,
    WorkflowStepSummary,
    WorkflowSummary,
)
from testudo.server.rate_limit import RateLimiter, RateLimitMiddleware


def create_app(
    *,
    runs_root: Path,
    workflows_root: Path | None = None,
    token: str | None = None,
    rate_limit: RateLimiter | None = None,
) -> FastAPI:
    """Build a FastAPI app for the testudo bridge.

    ``runs_root`` is created if missing. ``token`` defaults to a fresh url-safe
    string; pass an explicit value for tests so client requests can be
    pre-authorised. ``workflows_root`` defaults to ``./workflows`` if unset.
    """
    runs_root = Path(runs_root).resolve()
    runs_root.mkdir(parents=True, exist_ok=True)
    workflows_root = (workflows_root or Path("workflows")).resolve()

    app = FastAPI(title="Testudo", version=__version__)
    app.add_middleware(RateLimitMiddleware, limiter=rate_limit or RateLimiter())
    auth = TokenAuth(token=token or generate_token())
    runs: dict[str, RunResponse] = {}

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(version=__version__)

    @app.get(
        "/workflows",
        response_model=list[WorkflowSummary],
        dependencies=[Depends(auth)],
    )
    def list_workflows() -> list[WorkflowSummary]:
        if not workflows_root.is_dir():
            return []
        out: list[WorkflowSummary] = []
        for path in sorted(workflows_root.glob("*.json")):
            try:
                wf = load_workflow(path)
            except Exception:
                continue
            out.append(
                WorkflowSummary(
                    name=wf.name,
                    description=wf.description,
                    inputs={k: v.model_dump() for k, v in wf.inputs.items()},
                    step_count=len(wf.steps),
                    steps=[
                        WorkflowStepSummary(id=s.id, uses=s.uses, needs=list(s.needs))
                        for s in wf.steps
                    ],
                    path=str(path),
                )
            )
        return out

    @app.post(
        "/runs",
        response_model=RunResponse,
        dependencies=[Depends(auth)],
    )
    def create_run(request: RunRequest) -> RunResponse:
        workflow_path = Path(request.workflow_path)
        if not workflow_path.is_file():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Workflow not found: {workflow_path}",
            )

        try:
            wf = load_workflow(workflow_path)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to load workflow: {exc}",
            ) from exc

        run_id = request.run_id or secrets.token_hex(6)
        run_dir = runs_root / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        audit = AuditLog(run_dir / "audit.jsonl")
        executor = Executor(audit=audit)
        permissions = resolve_permissions(wf)

        results = executor.run(wf, request.inputs, permissions, run_id=run_id)

        any_error = any(r.error is not None for r in results.values())
        response = RunResponse(
            run_id=run_id,
            workflow_name=wf.name,
            status="failed" if any_error else "completed",
            results={
                k: StepResultPayload(output=v.output, skipped=v.skipped, error=v.error)
                for k, v in results.items()
            },
            audit_log=str(run_dir / "audit.jsonl"),
        )
        runs[run_id] = response
        return response

    @app.get(
        "/runs/{run_id}",
        response_model=RunResponse,
        dependencies=[Depends(auth)],
    )
    def get_run(run_id: str) -> RunResponse:
        if run_id not in runs:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Run not found: {run_id}",
            )
        return runs[run_id]

    return app
