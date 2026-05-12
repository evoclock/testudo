"""Regression test: POST /runs applies workflow input defaults.

Earlier the bridge passed `request.inputs` straight to the orchestrator,
which has no access to wf.inputs[key].default. Optional inputs with
defaults therefore failed at runtime even though the workflow schema
declared them. This test pins the bridge-side defaults application so a
silent regression is caught.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from testudo import _loaded  # noqa: F401
from testudo.server.app import create_app


@pytest.fixture
def workflow_with_defaults(tmp_path: Path) -> Path:
    """A workflow with one required input and one optional default."""
    wf = {
        "name": "defaults-smoke",
        "description": "regression for input defaults",
        "inputs": {
            "name": {"type": "string", "required": True},
            "greeting": {
                "type": "string",
                "required": False,
                "default": "hello",
            },
        },
        "steps": [
            {
                "id": "echo",
                "uses": "noop",
                "with": {"name": "${inputs.name}", "greeting": "${inputs.greeting}"},
            },
        ],
    }
    p = tmp_path / "defaults-smoke.json"
    p.write_text(json.dumps(wf), encoding="utf-8")
    return p


@pytest.fixture
def client_and_token(tmp_path: Path, workflow_with_defaults: Path) -> tuple[TestClient, str]:
    token = "defaults-token-aaaaaaaa"
    workflows_dir = tmp_path / "workflows"
    workflows_dir.mkdir()
    (workflows_dir / "defaults-smoke.json").write_text(
        workflow_with_defaults.read_text(encoding="utf-8")
    )
    app = create_app(
        runs_root=tmp_path / "runs",
        workflows_root=workflows_dir,
        token=token,
    )
    return TestClient(app), token


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_post_runs_applies_workflow_input_defaults(
    client_and_token: tuple[TestClient, str], workflow_with_defaults: Path
) -> None:
    """Caller omits the optional `greeting`; bridge fills the default."""
    client, token = client_and_token
    r = client.post(
        "/runs",
        headers=_headers(token),
        json={
            "workflow_path": str(workflow_with_defaults),
            "inputs": {"name": "alice"},  # greeting deliberately omitted
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "completed", body
    echoed = body["results"]["echo"]["output"]["echoed"]
    assert echoed == {"name": "alice", "greeting": "hello"}


def test_post_runs_caller_value_overrides_default(
    client_and_token: tuple[TestClient, str], workflow_with_defaults: Path
) -> None:
    """When the caller supplies the optional input, it wins over the default."""
    client, token = client_and_token
    r = client.post(
        "/runs",
        headers=_headers(token),
        json={
            "workflow_path": str(workflow_with_defaults),
            "inputs": {"name": "alice", "greeting": "hi there"},
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "completed", body
    echoed = body["results"]["echo"]["output"]["echoed"]
    assert echoed == {"name": "alice", "greeting": "hi there"}
