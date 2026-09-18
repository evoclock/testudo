# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""P1-P4 persistence tests: closed schema, atomic locked mutation, quarantine,
concurrent writers, bounds, and permissions."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import pytest

from testudo.seats.config import (
    MAX_HOSTS,
    MAX_SEATS_PER_HOST,
    ConflictError,
    SeatStore,
    StateStore,
    StoreCorruptError,
    empty_seats_config,
    empty_state,
    shared_endpoint_pairs,
    validate_pid_record,
    validate_seats_config,
)
from testudo.seats.validation import ValidationError

HOST_ID = "3f1c2a9e-7b4d-4e8a-9c21-5d0f6a8b1e34"
SEAT_A = "9a4b7c1d-2e5f-4a30-8b6c-1d2e3f4a5b60"
SEAT_B = "c07d5e2f-8a91-4b63-a5d7-6e7f8a9b0c1d"
SEAT_C = "d18e6f30-9ba2-4c74-b6e8-7f8091a2b3c4"

CONSENT = {
    "digest": "0" * 64,
    "accepted_at": "2026-09-15T00:00:00Z",
    "policy_version": 5,
    "ssh_effective_sha256": "0" * 64,
    "host_key_fingerprint": "SHA256:" + "A" * 43,
}


def full_config() -> dict:
    return {
        "schema": "testudo.seats.v1",
        "revision": 7,
        "hosts": [
            {
                "id": HOST_ID,
                "label": "spark",
                "ssh": {"kind": "alias", "alias": "spark"},
                "transport": {"kind": "ssh-tunnel"},
                "consent": dict(CONSENT),
                "seats": [
                    {
                        "id": SEAT_A,
                        "label": "unit-seat",
                        "template": "systemd-user",
                        "unit": "model.service",
                        "model_id": "example-model",
                        "port": 8000,
                        "endpoint_host": "127.0.0.1",
                        "ready_timeout": 600,
                    },
                    {
                        "id": SEAT_B,
                        "label": "script-seat",
                        "template": "control-script",
                        "script": "/home/user/.local/bin/model-control",
                        "start_subcommand": "start",
                        "stop_subcommand": "stop",
                        "status_subcommand": "status",
                        "model_id": "example-model",
                        "port": 8001,
                        "endpoint_host": "127.0.0.1",
                        "ready_timeout": 600,
                    },
                    {
                        "id": SEAT_C,
                        "label": "bare-seat",
                        "template": "bare-command",
                        "launch_argv": ["/home/user/bin/server", "--port", "8000"],
                        "cwd": "/home/user/models",
                        "ready_timeout": 600,
                        "model_id": "example-model",
                        "port": 8002,
                        "endpoint_host": "127.0.0.1",
                    },
                ],
            }
        ],
    }


class TestClosedSchema:
    def test_spec_example_validates(self) -> None:
        assert validate_seats_config(full_config())["revision"] == 7

    def test_unknown_root_member_rejected(self) -> None:
        config = full_config()
        config["extra"] = 1
        with pytest.raises(ValidationError):
            validate_seats_config(config)

    def test_unknown_host_member_rejected(self) -> None:
        config = full_config()
        config["hosts"][0]["extra"] = 1
        with pytest.raises(ValidationError):
            validate_seats_config(config)

    def test_unknown_seat_member_rejected(self) -> None:
        config = full_config()
        config["hosts"][0]["seats"][0]["extra"] = 1
        with pytest.raises(ValidationError):
            validate_seats_config(config)

    def test_cross_template_field_rejected(self) -> None:
        config = full_config()
        config["hosts"][0]["seats"][0]["script"] = "/x"  # systemd-user seat
        with pytest.raises(ValidationError):
            validate_seats_config(config)

    def test_missing_template_field_rejected(self) -> None:
        config = full_config()
        del config["hosts"][0]["seats"][0]["unit"]
        with pytest.raises(ValidationError):
            validate_seats_config(config)

    def test_consent_closed(self) -> None:
        config = full_config()
        config["hosts"][0]["consent"]["extra"] = 1
        with pytest.raises(ValidationError):
            validate_seats_config(config)

    def test_consent_null_allowed(self) -> None:
        config = full_config()
        config["hosts"][0]["consent"] = None
        assert validate_seats_config(config)

    def test_consent_policy_version_must_be_five(self) -> None:
        config = full_config()
        config["hosts"][0]["consent"]["policy_version"] = 4
        with pytest.raises(ValidationError):
            validate_seats_config(config)

    def test_transport_closed(self) -> None:
        for kind in ("trusted-lan", "https", "ssh-tunnel"):
            config = full_config()
            config["hosts"][0]["transport"] = {"kind": kind}
            assert validate_seats_config(config)
        config = full_config()
        config["hosts"][0]["transport"] = {"kind": "socks"}
        with pytest.raises(ValidationError):
            validate_seats_config(config)
        config = full_config()
        config["hosts"][0]["transport"] = {"kind": "https", "insecure": True}
        with pytest.raises(ValidationError):
            validate_seats_config(config)

    def test_explicit_ssh_descriptor(self) -> None:
        config = full_config()
        config["hosts"][0]["ssh"] = {
            "kind": "explicit",
            "user": "user",
            "host": "100.64.0.2",
            "port": 22,
            "key_path": "/home/user/.ssh/id_ed25519",
        }
        assert validate_seats_config(config)
        config["hosts"][0]["ssh"] = {"kind": "explicit", "user": "user", "host": "h", "port": 22}
        assert validate_seats_config(config)
        config["hosts"][0]["ssh"]["port"] = 0
        with pytest.raises(ValidationError):
            validate_seats_config(config)

    def test_uuid_uniqueness_and_class(self) -> None:
        config = full_config()
        config["hosts"][0]["seats"][1]["id"] = config["hosts"][0]["seats"][0]["id"]
        with pytest.raises(ValidationError):
            validate_seats_config(config)
        config = full_config()
        config["hosts"][0]["id"] = SEAT_A  # v4 class still, but duplicate
        with pytest.raises(ValidationError):
            validate_seats_config(config)

    def test_duplicate_endpoint_model_rejected_shared_port_allowed(self) -> None:
        config = full_config()
        # same endpoint+model as seat A
        config["hosts"][0]["seats"][1]["port"] = 8000
        with pytest.raises(ValidationError):
            validate_seats_config(config)
        # same endpoint, different model: allowed (with warning)
        config["hosts"][0]["seats"][1]["port"] = 8000
        config["hosts"][0]["seats"][1]["model_id"] = "other-model"
        assert validate_seats_config(config)
        assert (config["hosts"][0]["seats"][0]["endpoint_host"], 8000) in shared_endpoint_pairs(
            config
        )

    def test_cardinality_bounds(self) -> None:
        config = empty_seats_config()
        config["hosts"] = [
            {
                "id": HOST_ID,
                "label": "h",
                "ssh": {"kind": "alias", "alias": "h"},
                "transport": {"kind": "https"},
                "consent": None,
                "seats": [],
            }
            for _ in range(MAX_HOSTS + 1)
        ]
        with pytest.raises(ValidationError):
            validate_seats_config(config)

    def test_seat_per_host_bound(self) -> None:
        config = full_config()
        config["hosts"][0]["seats"] = [
            dict(
                config["hosts"][0]["seats"][0],
                id=f"9a4b7c1d-2e5f-4a30-8b6c-1d2e3f4a5b{i:02d}",
                port=9000 + i,
            )
            for i in range(MAX_SEATS_PER_HOST + 1)
        ]
        with pytest.raises(ValidationError):
            validate_seats_config(config)

    def test_ready_timeout_bounds(self) -> None:
        config = full_config()
        config["hosts"][0]["seats"][0]["ready_timeout"] = 29
        with pytest.raises(ValidationError):
            validate_seats_config(config)
        config["hosts"][0]["seats"][0]["ready_timeout"] = 1801
        with pytest.raises(ValidationError):
            validate_seats_config(config)

    def test_revision_bounds(self) -> None:
        config = full_config()
        config["revision"] = 9_007_199_254_740_992
        with pytest.raises(ValidationError):
            validate_seats_config(config)
        config["revision"] = -1
        with pytest.raises(ValidationError):
            validate_seats_config(config)


class TestSeatStore:
    def test_creates_empty_revision_zero(self, tmp_path: Path) -> None:
        store = SeatStore(tmp_path / "seats.v1.json")
        assert store.load() == empty_seats_config()

    def test_mutation_increments_revision(self, tmp_path: Path) -> None:
        store = SeatStore(tmp_path / "seats.v1.json")
        store.mutate(0, lambda config: config.update({"hosts": full_config()["hosts"]}))
        assert store.load()["revision"] == 1

    def test_revision_conflict(self, tmp_path: Path) -> None:
        store = SeatStore(tmp_path / "seats.v1.json")
        store.mutate(0, lambda config: None)
        with pytest.raises(ConflictError):
            store.mutate(0, lambda config: None)

    def test_parallel_writers_lose_no_successful_update(self, tmp_path: Path) -> None:
        store = SeatStore(tmp_path / "seats.v1.json")
        conflicts: list[int] = []
        successes: list[int] = []

        def writer(tag: int) -> None:
            for _ in range(10):
                try:
                    current = store.load()
                    store.mutate(
                        current["revision"],
                        lambda config: config["hosts"].append(
                            {
                                "id": f"3f1c2a9e-7b4d-4e8a-9c21-5d0f6a8b1e{tag:02d}",
                                "label": f"h{tag}",
                                "ssh": {"kind": "alias", "alias": f"h{tag}"},
                                "transport": {"kind": "https"},
                                "consent": None,
                                "seats": [],
                            }
                        ),
                    )
                    successes.append(tag)
                except ConflictError:
                    conflicts.append(tag)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        # No successful update is ever lost: every success corresponds to a
        # host present in the final file.
        final = store.load()
        labels = {host["label"] for host in final["hosts"]}
        assert len(successes) > 0
        for tag in successes:
            assert f"h{tag}" in labels
        assert final["revision"] == len(successes)

    def test_corrupt_json_quarantined(self, tmp_path: Path) -> None:
        path = tmp_path / "seats.v1.json"
        store = SeatStore(path)
        store.load()
        path.write_text("{not json")
        with pytest.raises(StoreCorruptError):
            store.load()
        quarantined = list(tmp_path.glob("seats.v1.json.quarantine-*"))
        assert len(quarantined) == 1
        assert quarantined[0].read_text() == "{not json"
        # fresh revision-0 config installed
        assert store.load() == empty_seats_config()

    def test_schema_invalid_quarantined(self, tmp_path: Path) -> None:
        path = tmp_path / "seats.v1.json"
        store = SeatStore(path)
        store.load()
        path.write_text(json.dumps({"schema": "wrong", "revision": 0, "hosts": []}))
        with pytest.raises(StoreCorruptError):
            store.load()
        assert store.load() == empty_seats_config()

    def test_oversized_file_quarantined(self, tmp_path: Path) -> None:
        path = tmp_path / "seats.v1.json"
        store = SeatStore(path)
        store.load()
        path.write_text("[" + "1" * (1024 * 1024 + 10) + "]")
        with pytest.raises(StoreCorruptError):
            store.load()

    def test_symlink_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "elsewhere.json"
        target.write_text("{}")
        path = tmp_path / "seats.v1.json"
        path.symlink_to(target)
        store = SeatStore(path)
        with pytest.raises(OSError):
            store.load()

    def test_file_mode_0600(self, tmp_path: Path) -> None:
        path = tmp_path / "seats.v1.json"
        store = SeatStore(path)
        store.load()
        assert os.stat(path).st_mode & 0o777 == 0o600
        assert os.stat(tmp_path).st_mode & 0o777 == 0o700


class TestStateStore:
    def test_roundtrip_pid_record(self, tmp_path: Path) -> None:
        store = StateStore(tmp_path / "state.v1.json")
        record = {
            "host_id": HOST_ID,
            "seat_id": SEAT_C,
            "ssh_hostname": "spark",
            "ssh_port": 22,
            "endpoint_host": "127.0.0.1",
            "endpoint_port": 8000,
            "pid": 1234,
            "pgid": 1234,
            "proc_start_ticks": 999999,
            "boot_id": "8f4c1e2a-9b3d-4c5e-8f6a-7b8c9d0e1f2a",
            "argv_sha256": "0" * 64,
        }
        validate_pid_record("record", record)
        store.mutate(0, lambda state: state["pid_records"].append(record))
        assert store.load()["pid_records"] == [record]

    def test_duplicate_seat_record_rejected(self, tmp_path: Path) -> None:
        store = StateStore(tmp_path / "state.v1.json")
        record = {
            "host_id": HOST_ID,
            "seat_id": SEAT_C,
            "ssh_hostname": "spark",
            "ssh_port": 22,
            "endpoint_host": "127.0.0.1",
            "endpoint_port": 8000,
            "pid": 1234,
            "pgid": 1234,
            "proc_start_ticks": 999999,
            "boot_id": "8f4c1e2a-9b3d-4c5e-8f6a-7b8c9d0e1f2a",
            "argv_sha256": "0" * 64,
        }

        def add_two(state: dict) -> None:
            state["pid_records"].append(record)
            state["pid_records"].append(dict(record))

        with pytest.raises(ValidationError):
            store.mutate(0, add_two)

    def test_pid_bounds(self, tmp_path: Path) -> None:
        store = StateStore(tmp_path / "state.v1.json")
        record = {
            "host_id": HOST_ID,
            "seat_id": SEAT_C,
            "ssh_hostname": "spark",
            "ssh_port": 22,
            "endpoint_host": "127.0.0.1",
            "endpoint_port": 8000,
            "pid": 0,  # invalid
            "pgid": 1234,
            "proc_start_ticks": 999999,
            "boot_id": "8f4c1e2a-9b3d-4c5e-8f6a-7b8c9d0e1f2a",
            "argv_sha256": "0" * 64,
        }
        with pytest.raises(ValidationError):
            store.mutate(0, lambda state: state["pid_records"].append(record))

    def test_discovery_history_rejected_from_state(self, tmp_path: Path) -> None:
        store = StateStore(tmp_path / "state.v1.json")
        with pytest.raises(ValidationError):
            store.mutate(
                0,
                lambda state: state.update(
                    {"discovery_history": [{"candidate": "x", "ports": [8000]}]}
                ),
            )

    def test_corrupt_state_quarantined(self, tmp_path: Path) -> None:
        path = tmp_path / "state.v1.json"
        store = StateStore(path)
        store.load()
        path.write_text("nonsense")
        with pytest.raises(StoreCorruptError):
            store.load()
        assert store.load() == empty_state()
