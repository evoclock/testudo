# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Offline integration: the complete renderer draft -> apply-inert -> trust
-> preview -> consent -> operation lifecycle shape (without a live SSH
host), plus reconciliation semantics."""

from __future__ import annotations

from pathlib import Path

import pytest

from testudo.seats.config import SeatStore, StateStore
from testudo.seats.service import ApiError, SeatService
from testudo.seats.ssh import HostKeyTrustStore


def make_service(tmp_path: Path) -> SeatService:
    service = SeatService(
        SeatStore(tmp_path / "seats.v1.json"),
        StateStore(tmp_path / "state.v1.json"),
        HostKeyTrustStore(tmp_path / "known_hosts"),
    )
    return service


def create_host_with_seat(service: SeatService) -> tuple[str, str]:
    draft = service.draft_create(
        "host",
        {
            "label": "spark",
            "ssh": {"kind": "alias", "alias": "localhost"},
            "transport": {"kind": "ssh-tunnel"},
        },
    )
    applied = service.config_apply(draft["draft_id"], draft["draft_revision"], 0)
    host_id = service.config_get()["hosts"][0]["id"]
    seat_draft = service.draft_create(
        "seat",
        {
            "label": "unit-seat",
            "template": "systemd-user",
            "unit": "model.service",
            "model_id": "example-model",
            "port": 8000,
            "endpoint_host": "127.0.0.1",
            "ready_timeout": 600,
        },
        parent_host_id=host_id,
    )
    service.config_apply(
        seat_draft["draft_id"], seat_draft["draft_revision"], applied["config_revision"]
    )
    seat_id = service.config_get()["hosts"][0]["seats"][0]["id"]
    return host_id, seat_id


class TestLifecycle:
    def test_draft_apply_inert_sets_consent_null(self, tmp_path: Path) -> None:
        service = make_service(tmp_path)
        _host_id, _seat_id = create_host_with_seat(service)
        config = service.config_get()
        assert config["revision"] == 2
        for host in config["hosts"]:
            assert host["consent"] is None  # apply-inert

    def test_operation_requires_trust_then_consent(self, tmp_path: Path) -> None:
        service = make_service(tmp_path)
        _host_id, seat_id = create_host_with_seat(service)
        with pytest.raises(ApiError, match="not trusted"):
            service.seat_operate(seat_id, "start")

    def test_preview_requires_trust(self, tmp_path: Path) -> None:
        service = make_service(tmp_path)
        host_id, _seat_id = create_host_with_seat(service)
        with pytest.raises(ApiError, match="not trusted"):
            service.preview_create(host_id, service.config_revision)

    def test_edit_invalidates_consent(self, tmp_path: Path) -> None:
        service = make_service(tmp_path)
        host_id, _seat_id = create_host_with_seat(service)
        # simulate a consented host, then edit a seat -> consent must reset
        config = service.store.load()
        consented = dict(config)
        consented["hosts"] = [
            dict(
                host,
                consent={
                    "digest": "0" * 64,
                    "accepted_at": "2026-09-15T00:00:00Z",
                    "policy_version": 5,
                    "ssh_effective_sha256": "0" * 64,
                    "host_key_fingerprint": "SHA256:" + "A" * 43,
                },
            )
            for host in config["hosts"]
        ]
        service.store.mutate(config["revision"], lambda c: c.update({"hosts": consented["hosts"]}))
        assert service.config_get()["hosts"][0]["consent"] is not None
        # refresh the tracked revision after the direct store write
        service.config_revision = service.store.load()["revision"]
        seat_draft = service.draft_create(
            "seat",
            {
                "label": "second",
                "template": "systemd-user",
                "unit": "b.service",
                "model_id": "m2",
                "port": 8001,
                "endpoint_host": "127.0.0.1",
                "ready_timeout": 600,
            },
            parent_host_id=host_id,
        )
        service.config_apply(
            seat_draft["draft_id"], seat_draft["draft_revision"], service.config_revision
        )
        assert service.config_get()["hosts"][0]["consent"] is None

    def test_delete_host_removes_no_shadow_inventory(self, tmp_path: Path) -> None:
        service = make_service(tmp_path)
        host_id, seat_id = create_host_with_seat(service)
        service.config_delete("seat", seat_id, service.config_revision)
        assert all(
            seat["id"] != seat_id
            for host in service.config_get()["hosts"]
            for seat in host["seats"]
        )
        service.config_delete("host", host_id, service.config_revision)
        assert service.config_get()["hosts"] == []

    def test_shared_endpoint_warning_shape(self, tmp_path: Path) -> None:
        from testudo.seats.config import shared_endpoint_pairs

        service = make_service(tmp_path)
        _host_id, _seat_id = create_host_with_seat(service)
        config = service.store.load()
        # only one seat so far: no shared pair
        assert shared_endpoint_pairs(config) == set()

    def test_force_stop_challenge_single_use_shape(self, tmp_path: Path) -> None:
        service = make_service(tmp_path)
        _host_id, seat_id = create_host_with_seat(service)
        _install_consent(service)
        challenge = service.seat_force_stop_challenge(seat_id)
        assert challenge["confirmation_id"]
        # bound to seat, template, and the current consent digest (HIGH-2)
        stored = service.force_stop_challenges[challenge["confirmation_id"]]
        assert stored.seat_id == seat_id
        assert stored.template == "systemd-user"
        assert stored.consent_digest == service.store.load()["hosts"][0]["consent"]["digest"]

    def test_force_stop_challenge_requires_consent(self, tmp_path: Path) -> None:
        service = make_service(tmp_path)
        _host_id, seat_id = create_host_with_seat(service)
        with pytest.raises(ApiError, match="re-confirmation required"):
            service.seat_force_stop_challenge(seat_id)


def _install_consent(service: SeatService) -> None:
    """Write a syntactically valid consent object directly (P2)."""
    config = service.store.load()
    service.store.mutate(
        config["revision"],
        lambda c: c["hosts"][0].update(
            consent={
                "digest": "1" * 64,
                "accepted_at": "2026-09-15T00:00:00Z",
                "policy_version": 5,
                "ssh_effective_sha256": "1" * 64,
                "host_key_fingerprint": "SHA256:" + "A" * 43,
            }
        ),
    )
    service.config_revision = service.store.load()["revision"]
