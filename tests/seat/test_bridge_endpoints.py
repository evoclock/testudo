# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bridge endpoint tests: seat-control routes registered, authenticated,
and mapping to the section 6 service."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from testudo.server.app import create_app


@pytest.fixture()
def client(tmp_path: Path, monkeypatch) -> TestClient:
    monkeypatch.setenv("TESTUDO_DATA_DIR", str(tmp_path / "data"))
    os.makedirs(tmp_path / "runs", exist_ok=True)
    app = create_app(runs_root=tmp_path / "runs", token="test-token")
    return TestClient(app)


AUTH = {"Authorization": "Bearer test-token"}


class TestSeatEndpoints:
    def test_config_get_requires_auth(self, client: TestClient) -> None:
        response = client.get("/seats/config")
        assert response.status_code == 401

    def test_config_get_empty(self, client: TestClient) -> None:
        response = client.get("/seats/config", headers=AUTH)
        assert response.status_code == 200
        body = response.json()
        assert body["schema"] == "testudo.seats.v1"
        assert body["revision"] == 0
        assert body["hosts"] == []

    def test_draft_create_rejects_generated_fields(self, client: TestClient) -> None:
        response = client.post(
            "/seats/draft",
            headers=AUTH,
            json={
                "kind": "host",
                "fields": {
                    "id": "00000000-0000-4000-8000-000000000000",
                    "label": "x",
                    "ssh": {"kind": "alias", "alias": "h"},
                    "transport": {"kind": "https"},
                },
            },
        )
        assert response.status_code == 400
        assert "bridge-generated" in response.json()["detail"]

    def test_draft_create_validates_fields(self, client: TestClient) -> None:
        response = client.post(
            "/seats/draft",
            headers=AUTH,
            json={
                "kind": "host",
                "fields": {
                    "label": "bad\tlabel",
                    "ssh": {"kind": "alias", "alias": "h"},
                    "transport": {"kind": "https"},
                },
            },
        )
        assert response.status_code == 400

    def test_apply_conflict_maps_to_409(self, client: TestClient) -> None:
        draft = client.post(
            "/seats/draft",
            headers=AUTH,
            json={
                "kind": "host",
                "fields": {
                    "label": "h",
                    "ssh": {"kind": "alias", "alias": "h"},
                    "transport": {"kind": "https"},
                },
            },
        ).json()
        response = client.post(
            "/seats/config/apply",
            headers=AUTH,
            json={
                "draft_id": draft["draft_id"],
                "draft_revision": draft["draft_revision"],
                "expected_config_revision": 99,
            },
        )
        assert response.status_code == 409

    def test_full_draft_apply_cycle(self, client: TestClient) -> None:
        draft = client.post(
            "/seats/draft",
            headers=AUTH,
            json={
                "kind": "host",
                "fields": {
                    "label": "spark",
                    "ssh": {"kind": "alias", "alias": "localhost"},
                    "transport": {"kind": "ssh-tunnel"},
                },
            },
        ).json()
        applied = client.post(
            "/seats/config/apply",
            headers=AUTH,
            json={
                "draft_id": draft["draft_id"],
                "draft_revision": draft["draft_revision"],
                "expected_config_revision": 0,
            },
        )
        assert applied.status_code == 200
        config = client.get("/seats/config", headers=AUTH).json()
        assert len(config["hosts"]) == 1
        assert config["hosts"][0]["consent"] is None
        assert config["revision"] == 1

    def test_provider_key_state_never_returns_key_bytes(self, client: TestClient) -> None:
        response = client.post(
            "/seats/provider-key/state", headers=AUTH, json={"provider_id": "openai"}
        )
        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"provider_id", "state"}
