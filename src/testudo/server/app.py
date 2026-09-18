# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

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
import sys
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from testudo import __version__, _loaded  # noqa: F401  - registers built-in tools
from testudo.audit import AuditLog
from testudo.orchestrator import (
    Executor,
    load_workflow,
    resolve_isolation,
    resolve_permissions,
)
from testudo.runtime.backend import ExecutionBackend
from testudo.runtime.runner import Runner, RunnerResult
from testudo.server.auth import TokenAuth, generate_token
from testudo.server.models import (
    EnvCheckResponse,
    HealthResponse,
    ModelEntry,
    ModelProviderStatus,
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
    runner: Runner | None = None,
    backend: str | ExecutionBackend | None = None,
) -> FastAPI:
    """Build a FastAPI app for the testudo bridge.

    ``runs_root`` is created if missing. ``token`` defaults to a fresh url-safe
    string; pass an explicit value for tests so client requests can be
    pre-authorised. ``workflows_root`` defaults to ``./workflows`` if unset.
    The default ``microvm`` backend fails closed until a host-supervisor-owned
    ``Runner`` is injected; ``direct`` is an explicit compatibility mode.
    """
    runs_root = Path(runs_root).resolve()
    runs_root.mkdir(parents=True, exist_ok=True)
    workflows_root = (workflows_root or Path("workflows")).resolve()
    selected_backend = _normalise_backend(
        backend if backend is not None else (runner.backend if runner is not None else "microvm")
    )
    if selected_backend == "direct" and runner is not None:
        raise ValueError("direct backend cannot be combined with a configured Runner")

    app = FastAPI(title="Testudo", version=__version__)
    # Allow the Electron renderer (vite dev on :5173, or file:// in
    # production) to call the bridge across origins. Auth is still
    # bearer-token gated; the bridge listens only on 127.0.0.1 so even
    # an open allow-list cannot be reached from off-host.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
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

    @app.get(
        "/workflows/{name}/readme",
        dependencies=[Depends(auth)],
    )
    def get_workflow_readme(name: str) -> dict[str, str | None]:
        """Return the per-workflow README markdown if one exists.

        Looks under ``<workflows_root>/readmes/<name>.md``. Returns
        ``{"name": ..., "readme": null}`` when the workflow has no
        README; callers decide whether to fall back to the inline
        description.
        """
        # Defence against path traversal: require kebab-case + dots
        if not re.fullmatch(r"[a-z0-9][a-z0-9.\-]{0,80}", name):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="workflow name must be kebab-case with optional dots",
            )
        readme_path = workflows_root / "readmes" / f"{name}.md"
        if not readme_path.is_file():
            return {"name": name, "readme": None}
        return {"name": name, "readme": readme_path.read_text(encoding="utf-8")}

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

        # Apply workflow input defaults for any key the caller did not
        # supply. Required because the orchestrator's reference resolver
        # has no access to wf.inputs[key].default; ${inputs.X} fails if
        # X is absent regardless of the schema-level default.
        merged_inputs: dict[str, object] = {}
        for key, spec in wf.inputs.items():
            if spec.default is not None:
                merged_inputs[key] = spec.default
        merged_inputs.update(request.inputs)

        run_id = request.run_id or secrets.token_hex(6)
        if not _safe_run_id(run_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="run_id must be 1-64 safe identifier characters",
            )

        if runner is not None:
            try:
                runtime_result = runner.run(
                    workflow_path=workflow_path,
                    workflow_name=wf.name,
                    isolation=resolve_isolation(wf),
                    backend=selected_backend,
                    run_id=run_id,
                    inputs=merged_inputs,
                )
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=f"Contained runtime failed to start or complete: {exc}",
                ) from exc
            response = _run_response_from_runtime(
                run_id=run_id,
                workflow_name=wf.name,
                runs_root=runs_root,
                result=runtime_result,
            )
            runs[run_id] = response
            return response

        if selected_backend != "direct":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    f"{selected_backend} backend selected but no configured host Runner is available"
                ),
            )

        run_dir = runs_root / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        audit = AuditLog(run_dir / "audit.jsonl")
        executor = Executor(audit=audit)
        permissions = resolve_permissions(wf)
        results = executor.run(wf, merged_inputs, permissions, run_id=run_id)

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

    _register_seat_endpoints(app, auth)

    return app


def _register_seat_endpoints(app: FastAPI, auth: TokenAuth) -> None:
    """Section 6 seat-control endpoints (spec: closed capability API).

    The renderer never supplies digests, commands, previews, or consent
    state; it may only echo an id, revision, or opaque challenge returned by
    the bridge in the exact endpoint field that requires it (R1).
    """
    from testudo.seats.config import SeatStore, StateStore
    from testudo.seats.runtime_dirs import data_dir
    from testudo.seats.service import ApiError, SeatService
    from testudo.seats.ssh import HostKeyTrustStore

    data_root = Path(data_dir())
    service = SeatService(
        store=SeatStore(data_root / "seats.v1.json"),
        state_store=StateStore(data_root / "state.v1.json"),
        trust_store=HostKeyTrustStore(data_root / "known_hosts"),
    )

    def _api_error(exc: ApiError, code: int) -> HTTPException:
        return HTTPException(status_code=code, detail=f"{exc.code}: {exc.message}")

    @app.post("/seats/draft", dependencies=[Depends(auth)])
    def seats_draft_create(body: dict[str, Any]) -> dict[str, Any]:
        try:
            return service.draft_create(
                body.get("kind", ""),
                body.get("fields", {}),
                parent_host_id=body.get("parent_host_id"),
                base_id=body.get("base_id"),
            )
        except ApiError as exc:
            raise _api_error(exc, status.HTTP_400_BAD_REQUEST) from exc

    @app.post("/seats/draft/update", dependencies=[Depends(auth)])
    def seats_draft_update(body: dict[str, Any]) -> dict[str, Any]:
        try:
            return service.draft_update(
                body.get("draft_id", ""),
                int(body.get("draft_revision", -1)),
                body.get("patch", {}),
            )
        except ApiError as exc:
            raise _api_error(exc, status.HTTP_400_BAD_REQUEST) from exc

    @app.post("/seats/config/apply", dependencies=[Depends(auth)])
    def seats_config_apply(body: dict[str, Any]) -> dict[str, Any]:
        try:
            return service.config_apply(
                body.get("draft_id", ""),
                int(body.get("draft_revision", -1)),
                int(body.get("expected_config_revision", -1)),
            )
        except ApiError as exc:
            raise _api_error(exc, status.HTTP_409_CONFLICT) from exc

    @app.post("/seats/config/delete", dependencies=[Depends(auth)])
    def seats_config_delete(body: dict[str, Any]) -> dict[str, Any]:
        try:
            return service.config_delete(
                body.get("kind", ""),
                body.get("id", ""),
                int(body.get("expected_config_revision", -1)),
            )
        except ApiError as exc:
            raise _api_error(exc, status.HTTP_409_CONFLICT) from exc

    @app.get("/seats/config", dependencies=[Depends(auth)])
    def seats_config_get() -> dict[str, Any]:
        return service.config_get()

    @app.post("/seats/ssh/probe", dependencies=[Depends(auth)])
    def seats_ssh_probe(body: dict[str, Any]) -> dict[str, Any]:
        try:
            return service.ssh_probe(
                body.get("host_id", ""), int(body.get("expected_config_revision", -1))
            )
        except ApiError as exc:
            raise _api_error(exc, status.HTTP_400_BAD_REQUEST) from exc

    @app.post("/seats/ssh/trust", dependencies=[Depends(auth)])
    def seats_ssh_trust(body: dict[str, Any]) -> dict[str, Any]:
        try:
            return service.ssh_trust(body.get("trust_challenge_id", ""))
        except ApiError as exc:
            raise _api_error(exc, status.HTTP_400_BAD_REQUEST) from exc

    @app.post("/seats/preview", dependencies=[Depends(auth)])
    def seats_preview_create(body: dict[str, Any]) -> dict[str, Any]:
        try:
            return service.preview_create(
                body.get("host_id", ""), int(body.get("expected_config_revision", -1))
            )
        except ApiError as exc:
            raise _api_error(exc, status.HTTP_400_BAD_REQUEST) from exc

    @app.post("/seats/consent", dependencies=[Depends(auth)])
    def seats_consent_confirm(body: dict[str, Any]) -> dict[str, Any]:
        try:
            return service.consent_confirm(body.get("preview_id", ""))
        except ApiError as exc:
            raise _api_error(exc, status.HTTP_400_BAD_REQUEST) from exc

    @app.post("/seats/operate", dependencies=[Depends(auth)])
    def seats_operate(body: dict[str, Any]) -> dict[str, Any]:
        try:
            return service.seat_operate(
                body.get("seat_id", ""),
                body.get("operation", ""),
                body.get("confirmation_id"),
            )
        except ApiError as exc:
            raise _api_error(exc, status.HTTP_400_BAD_REQUEST) from exc

    @app.post("/seats/inspect", dependencies=[Depends(auth)])
    def seats_inspect(body: dict[str, Any]) -> dict[str, Any]:
        try:
            return service.seat_inspect(body.get("seat_id", ""))
        except ApiError as exc:
            raise _api_error(exc, status.HTTP_400_BAD_REQUEST) from exc

    @app.post("/seats/force-stop-challenge", dependencies=[Depends(auth)])
    def seats_force_stop_challenge(body: dict[str, Any]) -> dict[str, Any]:
        try:
            return service.seat_force_stop_challenge(body.get("seat_id", ""))
        except ApiError as exc:
            raise _api_error(exc, status.HTTP_400_BAD_REQUEST) from exc

    @app.post("/seats/provider-key", dependencies=[Depends(auth)])
    def seats_provider_key_write(body: dict[str, Any]) -> dict[str, Any]:
        try:
            return service.provider_key_write(body.get("provider_id", ""), body.get("key", ""))
        except ApiError as exc:
            raise _api_error(exc, status.HTTP_400_BAD_REQUEST) from exc

    @app.post("/seats/provider-key/state", dependencies=[Depends(auth)])
    def seats_provider_key_state(body: dict[str, Any]) -> dict[str, Any]:
        return service.provider_key_state(body.get("provider_id", ""))


_SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")
_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def _safe_workflow_name(name: str) -> bool:
    return bool(_SAFE_NAME.match(name))


def _safe_run_id(run_id: str) -> bool:
    return bool(_SAFE_RUN_ID.fullmatch(run_id))


def _normalise_backend(value: str | ExecutionBackend) -> str:
    selected = value.value if isinstance(value, ExecutionBackend) else value
    if selected not in {"direct", "docker", "microvm"}:
        raise ValueError(f"unsupported execution backend: {selected!r}")
    return selected


def _run_response_from_runtime(
    *,
    run_id: str,
    workflow_name: str,
    runs_root: Path,
    result: RunnerResult,
) -> RunResponse:
    """Decode the guest's structured workflow result into the bridge shape."""
    payload: object = None
    if result.stdout.strip():
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            payload = None

    results: dict[str, StepResultPayload] = {}
    guest_status = result.exit_status
    if isinstance(payload, dict):
        raw_status = payload.get("exit_status")
        if isinstance(raw_status, int) and not isinstance(raw_status, bool):
            guest_status = raw_status
        raw_steps = payload.get("steps")
        if isinstance(raw_steps, dict):
            for step_id, raw_step in raw_steps.items():
                if not isinstance(step_id, str) or not isinstance(raw_step, dict):
                    continue
                results[step_id] = StepResultPayload(
                    output=raw_step.get("output"),
                    skipped=bool(raw_step.get("skipped", False)),
                    error=raw_step.get("error") if isinstance(raw_step.get("error"), str) else None,
                )

    if not results:
        results["__runtime__"] = StepResultPayload(
            output=result.stdout or None,
            error=result.stderr
            or (f"runtime exited with status {guest_status}" if guest_status else None),
        )

    any_error = guest_status != 0 or any(item.error is not None for item in results.values())
    return RunResponse(
        run_id=run_id,
        workflow_name=workflow_name,
        status="failed" if any_error else "completed",
        results=results,
        audit_log=str(runs_root / run_id / "audit.jsonl"),
    )


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


REGISTRY_SCHEMA = "testudo.model-registry.v1"
_REGISTRY_PATH_ENV = "TESTUDO_MODEL_REGISTRY"


def _registry_path() -> Path:
    """Resolve the model registry path.

    Order: TESTUDO_MODEL_REGISTRY override, then the user-editable copy in
    the platform userData directory (packaged installs), then the bundled
    repo default. Users edit the userData copy; the packaged one is a
    starting point.
    """
    override = os.environ.get(_REGISTRY_PATH_ENV)
    if override:
        return Path(override)
    user_copy = _user_registry_path()
    if user_copy.is_file():
        return user_copy
    packaged = Path(__file__).resolve().parent.parent.parent / "config" / "model-registry.v1.json"
    if packaged.is_file():
        return packaged
    return Path("config/model-registry.v1.json")


def _user_registry_path() -> Path:
    return _user_data_dir() / "model-registry.v1.json"


def _user_data_dir() -> Path:
    """Platform user-data directory; the packaged app keeps editable config here."""
    if sys.platform == "darwin":
        base = os.environ.get("HOME", "")
        return Path(base) / "Library" / "Application Support" / "testudo"
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "testudo"


def _probe_registry_provider(base_url: str) -> bool | None:
    """Probe one registry endpoint cheaply; None when unreachable/failed."""
    import httpx

    probe_url = base_url.rstrip("/")
    for suffix in ("/models", ""):
        try:
            response = httpx.get(probe_url + suffix, timeout=2.0)
            if response.status_code < 500:
                return True
        except httpx.HTTPError:
            continue
    return False


def _load_registry() -> list[ModelProviderStatus]:
    """Load the model registry or return an empty list without failing."""
    try:
        data = json.loads(_registry_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict) or data.get("schema") != REGISTRY_SCHEMA:
        return []
    providers: list[ModelProviderStatus] = []
    for raw in data.get("providers", []):
        if not isinstance(raw, dict):
            continue
        models = [
            ModelEntry(
                id=str(entry.get("id", "")),
                label=str(entry.get("label", entry.get("id", ""))),
                hint=str(entry.get("hint", "")),
                reasoning=bool(entry.get("reasoning", False)),
            )
            for entry in (raw.get("models", []) if isinstance(raw.get("models"), list) else [])
            if isinstance(entry, dict) and entry.get("id")
        ]
        base_url = str(raw.get("base_url", ""))
        providers.append(
            ModelProviderStatus(
                id=str(raw.get("id", "")),
                label=str(raw.get("label", raw.get("id", ""))),
                adapter=str(raw.get("adapter", "")),
                base_url=base_url,
                reachable=_probe_registry_provider(base_url) if base_url else None,
                models=models,
            )
        )
    return providers


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
        registry_providers=_load_registry(),
        databricks_env_set=databricks_env_set,
        file_ops_extra_installed=file_ops_installed,
        databricks_extra_installed=databricks_installed,
    )


def _annotation_str(annotation: object) -> str:
    if annotation is inspect.Parameter.empty:
        return "any"
    return getattr(annotation, "__name__", None) or str(annotation)
