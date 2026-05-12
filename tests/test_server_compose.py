"""Tests for the compose-mode bridge endpoints: GET /tools and POST /workflows."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from testudo import _loaded  # noqa: F401  - register tools
from testudo.server.app import create_app


@pytest.fixture
def client_and_token(tmp_path: Path) -> tuple[TestClient, str]:
    token = "compose-token-aaaaaaaa"
    workflows_dir = tmp_path / "workflows"
    workflows_dir.mkdir()
    app = create_app(
        runs_root=tmp_path / "runs",
        workflows_root=workflows_dir,
        token=token,
    )
    return TestClient(app), token


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_get_tools_requires_auth(client_and_token: tuple[TestClient, str]) -> None:
    client, _ = client_and_token
    assert client.get("/tools").status_code == 401


def test_get_tools_lists_registered_tools(client_and_token: tuple[TestClient, str]) -> None:
    client, token = client_and_token
    r = client.get("/tools", headers=_headers(token))
    assert r.status_code == 200
    tools = r.json()
    names = {t["name"] for t in tools}
    assert "connectors.local_file" in names
    assert "connectors.extract_document" in names
    assert "sanitisers.pii" in names
    assert "outputs.file" in names
    assert "models.ollama_chat" in names


def test_get_tools_returns_kwarg_signatures(
    client_and_token: tuple[TestClient, str],
) -> None:
    client, token = client_and_token
    tools = client.get("/tools", headers=_headers(token)).json()
    ollama = next(t for t in tools if t["name"] == "models.ollama_chat")
    param_names = {p["name"] for p in ollama["params"]}
    assert {"model", "prompt", "system", "temperature"}.issubset(param_names)
    model_param = next(p for p in ollama["params"] if p["name"] == "model")
    assert model_param["required"] is True
    temp_param = next(p for p in ollama["params"] if p["name"] == "temperature")
    assert temp_param["required"] is False
    assert temp_param["default"] == 0.0


def test_get_tools_excludes_ctx_parameter(client_and_token: tuple[TestClient, str]) -> None:
    client, token = client_and_token
    tools = client.get("/tools", headers=_headers(token)).json()
    for tool in tools:
        param_names = [p["name"] for p in tool["params"]]
        assert "_ctx" not in param_names
        assert "ctx" not in param_names


def test_post_workflows_saves_valid_draft(
    client_and_token: tuple[TestClient, str], tmp_path: Path
) -> None:
    client, token = client_and_token
    draft = {
        "name": "compose-smoke",
        "description": "Saved from compose mode",
        "inputs": {
            "path": {"type": "file", "required": True},
        },
        "steps": [
            {"id": "read", "uses": "connectors.local_file", "with": {"path": "${inputs.path}"}},
        ],
    }
    r = client.post("/workflows", headers=_headers(token), json=draft)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "compose-smoke"
    saved = Path(body["path"])
    assert saved.is_file()
    on_disk = json.loads(saved.read_text(encoding="utf-8"))
    assert on_disk["name"] == "compose-smoke"
    assert on_disk["steps"][0]["uses"] == "connectors.local_file"


def test_post_workflows_rejects_unsafe_name(
    client_and_token: tuple[TestClient, str],
) -> None:
    client, token = client_and_token
    for bad_name in ["../escape", "name with spaces", "Capital", "", "x" * 81]:
        r = client.post(
            "/workflows",
            headers=_headers(token),
            json={"name": bad_name, "steps": [{"id": "a", "uses": "noop", "with": {}}]},
        )
        assert r.status_code == 400, bad_name


def test_post_workflows_rejects_unknown_extra_field(
    client_and_token: tuple[TestClient, str],
) -> None:
    client, token = client_and_token
    r = client.post(
        "/workflows",
        headers=_headers(token),
        json={
            "name": "extra-field",
            "steps": [{"id": "a", "uses": "noop", "with": {}}],
            "bogus_field": 42,
        },
    )
    assert r.status_code == 422


def test_post_workflows_rejects_invalid_workflow_schema(
    client_and_token: tuple[TestClient, str],
) -> None:
    client, token = client_and_token
    # Missing 'uses' on the step should fail re-validation after save
    r = client.post(
        "/workflows",
        headers=_headers(token),
        json={
            "name": "broken-step",
            "steps": [{"id": "a", "with": {}}],
        },
    )
    # Pydantic field-required error; surfaces as 422 or our 400-with-message after save
    assert r.status_code in {400, 422}


def test_saved_workflow_appears_in_workflows_listing(
    client_and_token: tuple[TestClient, str],
) -> None:
    client, token = client_and_token
    client.post(
        "/workflows",
        headers=_headers(token),
        json={
            "name": "listable",
            "description": "should appear in GET /workflows",
            "inputs": {"x": {"type": "string", "required": True}},
            "steps": [
                {"id": "a", "uses": "connectors.local_file", "with": {"path": "${inputs.x}"}},
            ],
        },
    )
    r = client.get("/workflows", headers=_headers(token))
    assert r.status_code == 200
    names = [wf["name"] for wf in r.json()]
    assert "listable" in names
