# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""A1/A2/B1-B3/C3/C4/L3 controller unit tests: exact argv, ownership gate
shape, template differences, and PID-identity plumbing."""

from __future__ import annotations

from pathlib import Path

import pytest

from testudo.seats._scripts import C_PID_V1, EXEC_V1, LAUNCH_V1
from testudo.seats.controller import (
    BareCommandController,
    ControlScriptController,
    SeatContext,
    SystemdUserController,
    controller_for,
)
from testudo.seats.lifetime import LingerObservation
from testudo.seats.render import argv_sha256, remote_command
from testudo.seats.ssh import SshDescriptor

HOST_ID = "3f1c2a9e-7b4d-4e8a-9c21-5d0f6a8b1e34"
SEAT_A = "9a4b7c1d-2e5f-4a30-8b6c-1d2e3f4a5b60"
SEAT_B = "c07d5e2f-8a91-4b63-a5d7-6e7f8a9b0c1d"
SEAT_C = "d18e6f30-9ba2-4c74-b6e8-7f8091a2b3c4"


def make_context(seat: dict, tmp_path: Path) -> SeatContext:
    return SeatContext(
        host_id=HOST_ID,
        seat_id=seat["id"],
        seat=seat,
        descriptor=SshDescriptor("spark", None, None, str(tmp_path / "kh")),
        endpoint_host="127.0.0.1",
        endpoint_port=8000,
        ssh_hostname="spark",
        ssh_port=22,
        config_revision=1,
        poller=None,
        linger=LingerObservation("yes"),
    )


SEAT_A_DEF = {
    "id": SEAT_A,
    "label": "unit-seat",
    "template": "systemd-user",
    "unit": "model.service",
    "model_id": "example-model",
    "port": 8000,
    "endpoint_host": "127.0.0.1",
    "ready_timeout": 600,
}
SEAT_B_DEF = {
    "id": SEAT_B,
    "label": "script-seat",
    "template": "control-script",
    "script": "/home/user/.local/bin/model-control",
    "start_subcommand": "start",
    "stop_subcommand": "stop",
    "status_subcommand": "status",
    "model_id": "example-model",
    "port": 8000,
    "endpoint_host": "127.0.0.1",
    "ready_timeout": 600,
}
SEAT_C_DEF = {
    "id": SEAT_C,
    "label": "bare-seat",
    "template": "bare-command",
    "launch_argv": ["/home/user/bin/server", "--port", "8000"],
    "cwd": "/home/user/models",
    "ready_timeout": 600,
    "model_id": "example-model",
    "port": 8000,
    "endpoint_host": "127.0.0.1",
}


class TestTemplateAArgv:
    def test_start_argv(self, tmp_path: Path) -> None:
        controller = SystemdUserController(make_context(SEAT_A_DEF, tmp_path))
        assert controller._operation_argv("_start_locked") == [
            "systemctl",
            "--user",
            "start",
            "--",
            "model.service",
        ]

    def test_stop_argv(self, tmp_path: Path) -> None:
        controller = SystemdUserController(make_context(SEAT_A_DEF, tmp_path))
        assert controller._operation_argv("_stop_locked") == [
            "systemctl",
            "--user",
            "stop",
            "--",
            "model.service",
        ]

    def test_force_stop_argv(self, tmp_path: Path) -> None:
        controller = SystemdUserController(make_context(SEAT_A_DEF, tmp_path))
        assert controller._operation_argv("_force_stop_locked") == [
            "systemctl",
            "--user",
            "kill",
            "--signal=SIGKILL",
            "--",
            "model.service",
        ]

    def test_inspect_argv_exact(self, tmp_path: Path) -> None:
        controller = SystemdUserController(make_context(SEAT_A_DEF, tmp_path))
        argv = controller.inspect()["argv"]
        assert argv == [
            "systemctl",
            "--user",
            "show",
            "--no-pager",
            "--property=ActiveState",
            "--property=SubState",
            "--property=Result",
            "--property=NRestarts",
            "--property=Restart",
            "--",
            "model.service",
        ]
        assert controller.inspect()["remote"] == remote_command(EXEC_V1, argv)

    def test_diagnostics_argv(self, tmp_path: Path) -> None:
        controller = SystemdUserController(make_context(SEAT_A_DEF, tmp_path))
        remote = controller.diagnostics()
        assert "status" in remote and "--lines=10" in remote and "model.service" in remote


class TestTemplateB:
    def test_operation_argv_exact(self, tmp_path: Path) -> None:
        controller = ControlScriptController(make_context(SEAT_B_DEF, tmp_path))
        assert controller._operation_argv("_start_locked") == [
            "/home/user/.local/bin/model-control",
            "start",
        ]
        assert controller._operation_argv("_stop_locked") == [
            "/home/user/.local/bin/model-control",
            "stop",
        ]

    def test_status_via_exec_v1(self, tmp_path: Path) -> None:
        controller = ControlScriptController(make_context(SEAT_B_DEF, tmp_path))
        assert controller.status_argv() == [
            "/home/user/.local/bin/model-control",
            "status",
        ]
        assert "exec" in controller.inspect()["remote"]

    def test_no_force_stop(self, tmp_path: Path) -> None:
        controller = ControlScriptController(make_context(SEAT_B_DEF, tmp_path))
        outcome = controller.force_stop()
        assert outcome.state == "refused"
        assert outcome.error == "unsupported: host-side intervention required"


class TestTemplateC:
    def test_stop_argv_identity_checked(self, tmp_path: Path) -> None:
        from testudo.seats.config import StateStore

        state_store = StateStore(tmp_path / "state.v1.json")
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
            "argv_sha256": argv_sha256(SEAT_C_DEF["launch_argv"]),
        }
        state_store.mutate(0, lambda state: state["pid_records"].append(record))
        context = make_context(SEAT_C_DEF, tmp_path)
        context.state_store = state_store
        controller = BareCommandController(context)
        argv = controller._operation_argv("_stop_locked")
        assert argv[:2] == ["sh", "-c"]
        assert argv[2] == C_PID_V1
        assert argv[3] == "testudo"
        assert argv[4:6] == ["stop", "1234"]
        assert argv[6:] == [
            "1234",
            "999999",
            "8f4c1e2a-9b3d-4c5e-8f6a-7b8c9d0e1f2a",
            record["argv_sha256"],
        ]

    def test_stop_without_record_refuses(self, tmp_path: Path) -> None:
        context = make_context(SEAT_C_DEF, tmp_path)
        controller = BareCommandController(context)
        with pytest.raises(Exception, match="pid mismatch"):
            controller._operation_argv("_stop_locked")

    def test_start_argv_carries_expected_hash(self, tmp_path: Path) -> None:
        context = make_context(SEAT_C_DEF, tmp_path)
        controller = BareCommandController(context)
        argv = controller._operation_argv("_start_locked")
        assert argv[0] == "sh" and argv[1] == "-c" and argv[2] == LAUNCH_V1
        assert argv[4] == SEAT_C_DEF["cwd"]
        assert argv[5] == SEAT_C
        assert argv[6] == argv_sha256(SEAT_C_DEF["launch_argv"])
        assert argv[7:] == SEAT_C_DEF["launch_argv"]

    def test_log_tail_uses_log_tail_v1(self, tmp_path: Path) -> None:
        controller = BareCommandController(make_context(SEAT_C_DEF, tmp_path))
        remote = controller.log_tail_remote()
        assert "tail -c 4096" in remote
        assert SEAT_C in remote


class TestL3Gate:
    def test_post_lock_poll_exact_sole_model_permits(self, tmp_path: Path) -> None:
        from testudo.seats.transport import Observation

        context = make_context(SEAT_A_DEF, tmp_path)
        controller = SystemdUserController(context)
        context.poller = _FakePoller(
            [Observation(0, 0.0, "reachable", "closed", ("example-model",))]
        )
        assert controller._post_lock_poll() is True

    def test_post_lock_poll_different_model_refuses(self, tmp_path: Path) -> None:
        from testudo.seats.transport import Observation

        context = make_context(SEAT_A_DEF, tmp_path)
        controller = SystemdUserController(context)
        context.poller = _FakePoller([Observation(0, 0.0, "reachable", "closed", ("other-model",))])
        assert controller._post_lock_poll() is False

    def test_post_lock_poll_additional_models_refuse(self, tmp_path: Path) -> None:
        from testudo.seats.transport import Observation

        context = make_context(SEAT_A_DEF, tmp_path)
        controller = SystemdUserController(context)
        context.poller = _FakePoller(
            [Observation(0, 0.0, "reachable", "closed", ("example-model", "extra"))]
        )
        assert controller._post_lock_poll() is False

    def test_post_lock_poll_invalid_evidence_refuses(self, tmp_path: Path) -> None:
        from testudo.seats.transport import Observation

        context = make_context(SEAT_A_DEF, tmp_path)
        controller = SystemdUserController(context)
        for state in ("invalid", "unauthorized", "tls-error", "indeterminate"):
            context.poller = _FakePoller(
                [Observation(0, 0.0, "reachable", state, ("example-model",))]
            )
            assert controller._post_lock_poll() is False, state

    def test_start_refused_without_linger(self, tmp_path: Path) -> None:
        context = make_context(SEAT_A_DEF, tmp_path)
        context.linger = LingerObservation("no")
        controller = controller_for(context)
        outcome = controller.start()
        assert outcome.state == "refused"
        assert outcome.error == "host lifetime prerequisite"


class _FakePoller:
    def __init__(self, observations: list) -> None:
        self.observations = observations
        self.index = 0

    def poll(self, *args: object, **kwargs: object):
        observation = self.observations[min(self.index, len(self.observations) - 1)]
        self.index += 1
        return observation
