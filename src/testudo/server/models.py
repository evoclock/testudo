"""
Module: testudo.server.models

Purpose: Pydantic request and response models for the FastAPI bridge. Shared
across endpoints for request validation and OpenAPI schema generation.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

RunStatus = Literal["completed", "failed"]


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    version: str


class WorkflowStepSummary(BaseModel):
    """Minimal step shape for the DAG renderer."""

    id: str
    uses: str
    needs: list[str] = Field(default_factory=list)


class WorkflowSummary(BaseModel):
    """Brief description of a workflow available on disk."""

    name: str
    description: str | None = None
    inputs: dict[str, Any] = Field(default_factory=dict)
    step_count: int
    steps: list[WorkflowStepSummary] = Field(default_factory=list)
    path: str


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workflow_path: str
    inputs: dict[str, Any] = Field(default_factory=dict)
    run_id: str | None = None


class StepResultPayload(BaseModel):
    output: Any = None
    skipped: bool = False
    error: str | None = None


class RunResponse(BaseModel):
    run_id: str
    workflow_name: str
    status: RunStatus
    results: dict[str, StepResultPayload]
    audit_log: str


class ToolParam(BaseModel):
    """One keyword argument exposed by a registered tool."""

    name: str
    annotation: str = "any"
    default: Any = None
    has_default: bool = False
    required: bool = True


class ToolSummary(BaseModel):
    """A registered tool with its kwarg signature for the UI palette."""

    name: str
    module: str
    doc: str | None = None
    params: list[ToolParam] = Field(default_factory=list)


class WorkflowDraftStep(BaseModel):
    """One step in a workflow being authored from the UI."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    id: str
    uses: str
    needs: list[str] = Field(default_factory=list)
    with_: dict[str, Any] = Field(default_factory=dict, alias="with")


class WorkflowDraft(BaseModel):
    """Inbound shape for POST /workflows: the JSON the UI saves."""

    model_config = ConfigDict(extra="forbid")

    name: str
    description: str | None = None
    inputs: dict[str, Any] = Field(default_factory=dict)
    steps: list[dict[str, Any]]
    permissions: dict[str, Any] | None = None
    isolation: dict[str, Any] | None = None


class WorkflowSaveResponse(BaseModel):
    """Outbound shape for POST /workflows."""

    name: str
    path: str


class EnvCheckResponse(BaseModel):
    """Snapshot of the bridge's runtime environment.

    The renderer polls this once per launch (and on demand) so the user
    knows whether the LLM adapter, the Databricks adapter, etc. can
    actually run before they try a workflow that uses them.
    """

    ollama_url: str
    ollama_running: bool
    ollama_models: list[str] = Field(default_factory=list)
    ollama_error: str | None = None
    databricks_env_set: bool = False
    file_ops_extra_installed: bool = False
    databricks_extra_installed: bool = False
