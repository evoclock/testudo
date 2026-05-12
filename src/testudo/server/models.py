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
