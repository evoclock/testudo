"""Tests for ``testudo.server.app``: FastAPI endpoints + bearer-token auth."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from testudo.server.app import create_app


@pytest.fixture
def workflow_path(tmp_path: Path) -> Path:
    spec = {
        "name": "demo",
        "description": "Server test workflow",
        "inputs": {},
        "steps": [{"id": "a", "uses": "noop", "with": {"k": "v"}}],
    }
    p = tmp_path / "wf.json"
    p.write_text(json.dumps(spec), encoding="utf-8")
    return p


@pytest.fixture
def workflows_dir(tmp_path: Path, workflow_path: Path) -> Path:
    wfdir = tmp_path / "workflows"
    wfdir.mkdir()
    (wfdir / "demo.json").write_text(workflow_path.read_text(encoding="utf-8"))
    return wfdir


@pytest.fixture
def client_and_token(tmp_path: Path, workflows_dir: Path) -> tuple[TestClient, str]:
    token = "test-token-aaaaaaaa"
    app = create_app(
        runs_root=tmp_path / "runs",
        workflows_root=workflows_dir,
        token=token,
    )
    return TestClient(app), token


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_health_does_not_require_auth(
    client_and_token: tuple[TestClient, str],
) -> None:
    client, _ = client_and_token
    resp = client.get("/health")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["status"] == "ok"
    assert payload["version"]


def test_protected_endpoint_rejects_missing_token(
    client_and_token: tuple[TestClient, str],
) -> None:
    client, _ = client_and_token
    resp = client.get("/workflows")
    assert resp.status_code == 401


def test_protected_endpoint_rejects_wrong_token(
    client_and_token: tuple[TestClient, str],
) -> None:
    client, _ = client_and_token
    resp = client.get("/workflows", headers=_headers("wrong-token"))
    assert resp.status_code == 401


def test_workflows_endpoint_lists_directory(
    client_and_token: tuple[TestClient, str],
) -> None:
    client, token = client_and_token
    resp = client.get("/workflows", headers=_headers(token))
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["name"] == "demo"
    assert data[0]["step_count"] == 1


def test_create_run_executes_workflow(
    client_and_token: tuple[TestClient, str], workflow_path: Path
) -> None:
    client, token = client_and_token
    resp = client.post(
        "/runs",
        json={"workflow_path": str(workflow_path), "inputs": {}},
        headers=_headers(token),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "completed"
    assert body["workflow_name"] == "demo"
    assert "a" in body["results"]
    assert body["results"]["a"]["error"] is None


def test_create_run_404_on_missing_workflow(
    client_and_token: tuple[TestClient, str],
) -> None:
    client, token = client_and_token
    resp = client.post(
        "/runs",
        json={"workflow_path": "/nonexistent.json", "inputs": {}},
        headers=_headers(token),
    )
    assert resp.status_code == 404


def test_get_run_404_when_unknown(
    client_and_token: tuple[TestClient, str],
) -> None:
    client, token = client_and_token
    resp = client.get("/runs/ghost", headers=_headers(token))
    assert resp.status_code == 404


def test_get_run_returns_persisted_result(
    client_and_token: tuple[TestClient, str], workflow_path: Path
) -> None:
    client, token = client_and_token
    create = client.post(
        "/runs",
        json={"workflow_path": str(workflow_path), "inputs": {}},
        headers=_headers(token),
    )
    run_id = create.json()["run_id"]

    fetched = client.get(f"/runs/{run_id}", headers=_headers(token))
    assert fetched.status_code == 200
    assert fetched.json()["run_id"] == run_id
