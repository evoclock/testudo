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

import inspect
import json
import os
import re
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
    EnvCheckResponse,
    HealthResponse,
    RunRequest,
    RunResponse,
    StepResultPayload,
    ToolParam,
    ToolSummary,
    WorkflowDraft,
    WorkflowSaveResponse,
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

    @app.get(
        "/env-check",
        response_model=EnvCheckResponse,
        dependencies=[Depends(auth)],
    )
    def env_check() -> EnvCheckResponse:
        return _env_check()

    @app.get(
        "/tools",
        response_model=list[ToolSummary],
        dependencies=[Depends(auth)],
    )
    def list_tools() -> list[ToolSummary]:
        from testudo.orchestrator.registry import DEFAULT_REGISTRY

        out: list[ToolSummary] = []
        for name in sorted(DEFAULT_REGISTRY._tools):
            fn = DEFAULT_REGISTRY._tools[name]
            try:
                sig = inspect.signature(fn)
            except (TypeError, ValueError):
                continue
            params: list[ToolParam] = []
            for p_name, param in sig.parameters.items():
                if p_name in {"_ctx", "ctx"} or p_name.startswith("**"):
                    continue
                if param.kind in {
                    inspect.Parameter.VAR_POSITIONAL,
                    inspect.Parameter.VAR_KEYWORD,
                }:
                    continue
                has_default = param.default is not inspect.Parameter.empty
                params.append(
                    ToolParam(
                        name=p_name,
                        annotation=_annotation_str(param.annotation),
                        default=param.default if has_default else None,
                        has_default=has_default,
                        required=not has_default,
                    )
                )
            out.append(
                ToolSummary(
                    name=name,
                    module=getattr(fn, "__module__", "?"),
                    doc=(inspect.getdoc(fn) or None),
                    params=params,
                )
            )
        return out

    @app.post(
        "/workflows",
        response_model=WorkflowSaveResponse,
        dependencies=[Depends(auth)],
    )
    def save_workflow(draft: WorkflowDraft) -> WorkflowSaveResponse:
        from testudo.orchestrator import load_workflow as _load_workflow

        if not _safe_workflow_name(draft.name):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="workflow name must be kebab-case alphanumerics, 1-80 chars",
            )

        workflows_root.mkdir(parents=True, exist_ok=True)
        target = (workflows_root / f"{draft.name}.json").resolve()
        try:
            target.relative_to(workflows_root)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"workflow name resolves outside workflows root: {exc}",
            ) from exc

        payload = draft.model_dump(by_alias=True, exclude_none=True)
        target.write_text(
            json.dumps(payload, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )

        try:
            _load_workflow(target)
        except Exception as exc:
            target.unlink(missing_ok=True)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"workflow draft did not validate after save: {exc}",
            ) from exc

        return WorkflowSaveResponse(name=draft.name, path=str(target))

    return app


_SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")


def _safe_workflow_name(name: str) -> bool:
    return bool(_SAFE_NAME.match(name))


def _probe_ollama(url: str) -> tuple[bool, list[str], str | None]:
    """Hit the configured Ollama daemon's /api/tags endpoint.

    Returns ``(running, models, error_or_None)``. Pulled out as a
    module-level function so tests can monkeypatch it directly.
    """
    import httpx

    try:
        with httpx.Client(timeout=2.0) as client:
            r = client.get(f"{url.rstrip('/')}/api/tags")
            r.raise_for_status()
            data = r.json()
    except Exception as exc:
        return False, [], f"{type(exc).__name__}: {exc}"

    models: list[str] = []
    for model in data.get("models", []):
        name = model.get("name") or model.get("model")
        if isinstance(name, str):
            models.append(name)
    return True, models, None


def _env_check() -> EnvCheckResponse:
    """Inspect the runtime environment for adapter readiness.

    Pings the configured Ollama daemon, checks whether the Databricks
    env vars are set, and reports which optional extras are installed.
    The renderer surfaces the result so the user knows whether a given
    workflow has the deps it needs before they hit Run.
    """
    ollama_url = os.environ.get("TESTUDO_OLLAMA_URL", "http://localhost:11434")
    ollama_running, ollama_models, ollama_error = _probe_ollama(ollama_url)

    databricks_env_set = all(
        os.environ.get(key)
        for key in (
            "DATABRICKS_SERVER_HOSTNAME",
            "DATABRICKS_HTTP_PATH",
            "DATABRICKS_TOKEN",
        )
    )

    try:
        import pypdf  # noqa: F401

        try:
            import docx  # noqa: F401

            file_ops_installed = True
        except ImportError:
            file_ops_installed = False
    except ImportError:
        file_ops_installed = False

    try:
        import databricks.sql  # noqa: F401

        databricks_installed = True
    except ImportError:
        databricks_installed = False

    return EnvCheckResponse(
        ollama_url=ollama_url,
        ollama_running=ollama_running,
        ollama_models=sorted(ollama_models),
        ollama_error=ollama_error,
        databricks_env_set=databricks_env_set,
        file_ops_extra_installed=file_ops_installed,
        databricks_extra_installed=databricks_installed,
    )


def _annotation_str(annotation: object) -> str:
    if annotation is inspect.Parameter.empty:
        return "any"
    return getattr(annotation, "__name__", None) or str(annotation)
