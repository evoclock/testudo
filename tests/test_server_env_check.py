"""Tests for the /env-check bridge endpoint."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from testudo import _loaded  # noqa: F401
from testudo.server import app as app_module
from testudo.server.app import create_app


@pytest.fixture
def client_and_token(tmp_path: Path) -> tuple[TestClient, str]:
    token = "envcheck-token-aaaaaaaa"
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


def test_env_check_requires_auth(client_and_token: tuple[TestClient, str]) -> None:
    client, _ = client_and_token
    assert client.get("/env-check").status_code == 401


def test_env_check_reports_ollama_offline(
    client_and_token: tuple[TestClient, str], monkeypatch
) -> None:
    client, token = client_and_token
    monkeypatch.setattr(
        app_module,
        "_probe_ollama",
        lambda url: (False, [], "ConnectError: connection refused"),
    )
    body = client.get("/env-check", headers=_headers(token)).json()
    assert body["ollama_running"] is False
    assert body["ollama_error"] == "ConnectError: connection refused"
    assert body["ollama_models"] == []


def test_env_check_reports_ollama_online(
    client_and_token: tuple[TestClient, str], monkeypatch
) -> None:
    client, token = client_and_token
    monkeypatch.setattr(
        app_module,
        "_probe_ollama",
        lambda url: (True, ["llama3.2", "minimax-m2.5"], None),
    )
    body = client.get("/env-check", headers=_headers(token)).json()
    assert body["ollama_running"] is True
    assert body["ollama_models"] == ["llama3.2", "minimax-m2.5"]
    assert body["ollama_error"] is None


def test_env_check_databricks_env_set(
    client_and_token: tuple[TestClient, str], monkeypatch
) -> None:
    client, token = client_and_token
    monkeypatch.setattr(app_module, "_probe_ollama", lambda url: (False, [], "off"))
    monkeypatch.setenv("DATABRICKS_SERVER_HOSTNAME", "x.cloud.databricks.com")
    monkeypatch.setenv("DATABRICKS_HTTP_PATH", "/sql/1.0/warehouses/y")
    monkeypatch.setenv("DATABRICKS_TOKEN", "dapi-z")

    body = client.get("/env-check", headers=_headers(token)).json()
    assert body["databricks_env_set"] is True


def test_env_check_databricks_env_unset(
    client_and_token: tuple[TestClient, str], monkeypatch
) -> None:
    client, token = client_and_token
    monkeypatch.setattr(app_module, "_probe_ollama", lambda url: (False, [], "off"))
    monkeypatch.delenv("DATABRICKS_SERVER_HOSTNAME", raising=False)
    monkeypatch.delenv("DATABRICKS_HTTP_PATH", raising=False)
    monkeypatch.delenv("DATABRICKS_TOKEN", raising=False)

    body = client.get("/env-check", headers=_headers(token)).json()
    assert body["databricks_env_set"] is False
