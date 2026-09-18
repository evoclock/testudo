# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""BLK-1/BLK-5/BLK-6/BLK-3 tests: the guarded operation pipelines, the
inspect/readiness/stop parsers, PID-record persistence, and command-time
consent drift — driven through a fake GUARD_V1 controller so the full
L1 -> L2 -> L3 -> operation -> reconcile -> RELEASE path is exercised
without a live SSH host."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

import pytest

from testudo.seats import controller as controller_mod
from testudo.seats import service as service_mod
from testudo.seats._scripts import C_PID_V1, LAUNCH_V1
from testudo.seats.config import SeatStore, StateStore
from testudo.seats.consent import consent_digest
from testudo.seats.controller import (
    InvalidSystemdState,
    SeatContext,
    parse_pid_inspect,
    parse_status_exit,
    parse_systemctl_show,
    parse_testudo_pid,
)
from testudo.seats.guard import GuardOutcome
from testudo.seats.lifetime import LingerObservation
from testudo.seats.render import argv_sha256
from testudo.seats.service import ApiError, SeatService
from testudo.seats.ssh import EffectiveSsh, HostKeyTrustStore
from testudo.seats.transport import Observation

HOST_ID = "3f1c2a9e-7b4d-4e8a-9c21-5d0f6a8b1e34"
SEAT_A = "9a4b7c1d-2e5f-4a30-8b6c-1d2e3f4a5b60"
SEAT_C = "d18e6f30-9ba2-4c74-b6e8-7f8091a2b3c4"
FINGERPRINT = "SHA256:" + "A" * 43

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
SEAT_C_DEF = {
    "id": SEAT_C,
    "label": "bare-seat",
    "template": "bare-command",
    "launch_argv": ["/usr/local/bin/python3", "fixture_srv.py", "--port", "8000"],
    "cwd": "/opt/fixture",
    "ready_timeout": 600,
    "model_id": "example-model",
    "port": 8000,
    "endpoint_host": "127.0.0.1",
}

FAKE_EFFECTIVE = EffectiveSsh(
    (("hostname", "127.0.0.1"), ("port", "2222"), ("user", "fixture")),
    "/usr/bin/ssh",
    "OpenSSH_9.6",
    "0" * 64,
)


class FakePoller:
    """Deterministic endpoint poller: a queue of observations."""

    def __init__(self, observations: list[Observation]) -> None:
        self.observations = observations
        self.index = 0

    def poll(self, *args: object, **kwargs: object) -> Observation:
        observation = self.observations[min(self.index, len(self.observations) - 1)]
        self.index += 1
        return observation


def serving() -> Observation:
    return Observation(0, 0.0, "reachable", "closed", ("example-model",))


def empty() -> Observation:
    return Observation(0, 0.0, "reachable", "closed", ())


class FakeExecutor:
    """Deterministic read-only executor returning canned ExecResults."""

    def __init__(self, results: list[Any] | None = None) -> None:
        self.results = results or []
        self.index = 0
        self.calls: list[str] = []

    def __call__(self, remote: str) -> Any:
        self.calls.append(remote)
        from testudo.seats.ssh import ExecResult

        if not self.results:
            return ExecResult(0, "", "")
        result = self.results[min(self.index, len(self.results) - 1)]
        self.index += 1
        if isinstance(result, ExecResult):
            return result
        return ExecResult(0, result, "")


def show_result(
    active: str = "active",
    sub: str = "running",
    result: str = "success",
    restarts: int = 0,
    restart: str = "no",
) -> str:
    return (
        f"ActiveState={active}\nSubState={sub}\nResult={result}\n"
        f"NRestarts={restarts}\nRestart={restart}\n"
    )


class FakeGuard:
    """Fake GUARD_V1 controller driving the production hooks in order:
    poll_permits -> (operation) -> reconcile(raw output) -> outcome."""

    instances: ClassVar[list[FakeGuard]] = []

    def __init__(
        self,
        descriptor: object,
        lock_basename: str,
        nonce: str,
        *,
        poll_permits: Any = None,
        reconcile: Any = None,
        connect_timeout: int = 10,
    ) -> None:
        self.lock_basename = lock_basename
        self.nonce = nonce
        self.poll_permits = poll_permits or (lambda: True)
        self.reconcile = reconcile or (lambda raw: None)
        self.operation_argv: list[str] | None = None
        FakeGuard.instances.append(self)

    def operate(self, argv: list[str], *, timeout: float = 120.0) -> GuardOutcome:
        if not self.poll_permits():
            return GuardOutcome(True, 77, None, refused_reason="GATE_REFUSED")
        # the operation argv reaches the remote only after GO
        self.operation_argv = argv
        raw = self._operation_output(argv)
        result = GuardOutcome(True, 0, 0)
        result.operation_output = raw
        self.reconcile(raw)
        return result

    @staticmethod
    def _operation_output(argv: list[str]) -> str:
        if len(argv) > 2 and argv[2] == LAUNCH_V1:
            digest = argv_sha256(argv[7:])
            return f"TESTUDO_PID 4242 4242 999999 8f4c1e2a-9b3d-4c5e-8f6a-7b8c9d0e1f2a {digest}\n"
        return ""


@pytest.fixture(autouse=True)
def fake_guard(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    FakeGuard.instances = []
    monkeypatch.setattr(controller_mod, "GuardController", FakeGuard)
    monkeypatch.setattr(controller_mod, "_local_lock_path", lambda key: tmp_path / f"lock-{key}")


def make_context(
    seat: dict[str, Any],
    tmp_path: Path,
    *,
    poller: Any,
    state_store: StateStore | None = None,
    executor: Any = None,
) -> SeatContext:
    return SeatContext(
        host_id=HOST_ID,
        seat_id=seat["id"],
        seat=seat,
        descriptor=controller_mod.SshDescriptor(
            "fixture@127.0.0.1", 2222, None, str(tmp_path / "kh")
        ),
        endpoint_host=seat["endpoint_host"],
        endpoint_port=seat["port"],
        ssh_hostname="127.0.0.1",
        ssh_port=2222,
        config_revision=1,
        poller=poller,
        linger=LingerObservation("yes"),
        state_store=state_store,
        transport={"kind": "ssh-tunnel"},
        executor=executor,
    )


# --- BLK-1: start/stop/force_stop are real pipelines -------------------------


class TestGuardedPipelines:
    def test_start_no_longer_raises_attributeerror(self, tmp_path: Path) -> None:
        executor = FakeExecutor([show_result(), show_result()])
        context = make_context(
            SEAT_A_DEF, tmp_path, poller=FakePoller([empty(), serving()]), executor=executor
        )
        outcome = controller_mod.SystemdUserController(context).start()
        assert outcome.state == "serving"
        # the guard ran the exact Template A start argv
        assert FakeGuard.instances[-1].operation_argv == [
            "systemctl",
            "--user",
            "start",
            "--",
            "model.service",
        ]

    def test_stop_pipeline(self, tmp_path: Path) -> None:
        executor = FakeExecutor([show_result(active="inactive", sub="dead", result="success")])
        context = make_context(
            SEAT_A_DEF, tmp_path, poller=FakePoller([empty()]), executor=executor
        )
        outcome = controller_mod.SystemdUserController(context).stop()
        assert outcome.state == "dormant"
        assert FakeGuard.instances[-1].operation_argv == [
            "systemctl",
            "--user",
            "stop",
            "--",
            "model.service",
        ]

    def test_force_stop_pipeline(self, tmp_path: Path) -> None:
        executor = FakeExecutor([show_result(active="inactive", sub="dead", result="success")])
        context = make_context(
            SEAT_A_DEF, tmp_path, poller=FakePoller([empty()]), executor=executor
        )
        outcome = controller_mod.SystemdUserController(context).force_stop()
        assert outcome.state == "dormant"
        assert FakeGuard.instances[-1].operation_argv == [
            "systemctl",
            "--user",
            "kill",
            "--signal=SIGKILL",
            "--",
            "model.service",
        ]

    def test_a_start_readiness_activating_then_active(self, tmp_path: Path) -> None:
        executor = FakeExecutor(
            [
                show_result(active="activating", sub="start"),  # baseline before GO
                show_result(active="activating", sub="start"),  # first poll
                show_result(),  # active/running
            ]
        )
        context = make_context(
            SEAT_A_DEF, tmp_path, poller=FakePoller([empty(), serving()]), executor=executor
        )
        outcome = controller_mod.SystemdUserController(context).start()
        assert outcome.state == "serving"

    def test_a_start_restart_loop_is_error(self, tmp_path: Path) -> None:
        executor = FakeExecutor(
            [
                show_result(restarts=0),  # baseline
                show_result(restarts=3),  # increase from baseline: restart-loop
            ]
        )
        context = make_context(
            SEAT_A_DEF, tmp_path, poller=FakePoller([empty()]), executor=executor
        )
        outcome = controller_mod.SystemdUserController(context).start()
        assert outcome.state == "error"
        assert outcome.error == "restart-loop"

    def test_a_start_failed_unit_is_error(self, tmp_path: Path) -> None:
        executor = FakeExecutor(
            [
                show_result(active="inactive", sub="dead"),  # baseline
                show_result(active="failed", sub="failed", result="exit-code"),  # poll
            ]
        )
        context = make_context(
            SEAT_A_DEF, tmp_path, poller=FakePoller([empty()]), executor=executor
        )
        outcome = controller_mod.SystemdUserController(context).start()
        assert outcome.state == "error"
        assert "Result=exit-code" in outcome.detail

    def test_a_start_inactive_is_dormant(self, tmp_path: Path) -> None:
        executor = FakeExecutor(
            [
                show_result(active="inactive", sub="dead"),  # baseline
                show_result(active="inactive", sub="dead"),  # poll
            ]
        )
        context = make_context(
            SEAT_A_DEF, tmp_path, poller=FakePoller([empty()]), executor=executor
        )
        outcome = controller_mod.SystemdUserController(context).start()
        assert outcome.state == "dormant"

    def test_b_start_requires_endpoint_proof_beyond_status_claim(self, tmp_path: Path) -> None:
        from testudo.seats.ssh import ExecResult

        seat = {
            "id": "c07d5e2f-8a91-4b63-a5d7-6e7f8a9b0c1d",
            "label": "script-seat",
            "template": "control-script",
            "script": "/home/user/.local/bin/model-control",
            "start_subcommand": "start",
            "stop_subcommand": "stop",
            "status_subcommand": "status",
            "model_id": "example-model",
            "port": 8000,
            "endpoint_host": "127.0.0.1",
            "ready_timeout": 1,  # direct context: no config validation here
        }
        # status claims serving (exit 0) but the endpoint never reports the
        # exact model: serving is not confirmed; readiness times out instead
        executor = FakeExecutor([ExecResult(0, "", "")])
        context = make_context(seat, tmp_path, poller=FakePoller([empty()]), executor=executor)
        monkey = pytest.MonkeyPatch()
        monkey.setattr(controller_mod, "READY_POLL_INTERVAL", 0.02)
        try:
            outcome = controller_mod.ControlScriptController(context).start()
        finally:
            monkey.undo()
        assert outcome.state == "error"
        assert outcome.error == "readiness-timeout"

    def test_b_start_serving_with_endpoint_proof(self, tmp_path: Path) -> None:
        from testudo.seats.ssh import ExecResult

        seat = {
            "id": "c07d5e2f-8a91-4b63-a5d7-6e7f8a9b0c1d",
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
        executor = FakeExecutor([ExecResult(0, "", "")])
        context = make_context(seat, tmp_path, poller=FakePoller([serving()]), executor=executor)
        outcome = controller_mod.ControlScriptController(context).start()
        assert outcome.state == "serving"

    def test_b_stop_with_sole_model_runs_script(self, tmp_path: Path) -> None:
        seat = {
            "id": "c07d5e2f-8a91-4b63-a5d7-6e7f8a9b0c1d",
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
        # the L3 poll sees the exact sole model; after the stop the endpoint
        # no longer reports it
        poller = FakePoller([serving(), empty()])
        context = make_context(seat, tmp_path, poller=poller)
        outcome = controller_mod.ControlScriptController(context).stop()
        assert outcome.state == "dormant"
        assert FakeGuard.instances[-1].operation_argv == [
            "/home/user/.local/bin/model-control",
            "stop",
        ]
        seat = {
            "id": "c07d5e2f-8a91-4b63-a5d7-6e7f8a9b0c1d",
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
        # empty endpoint (dormant) refuses B stop: host-side intervention
        context = make_context(seat, tmp_path, poller=FakePoller([empty()]))
        outcome = controller_mod.ControlScriptController(context).stop()
        assert outcome.state == "refused"
        assert outcome.error == "host-side intervention required"
        # the gate refused before the script was ever invoked
        assert FakeGuard.instances[-1].operation_argv is None

    def test_unreachable_host_refuses_post_lock_poll(self, tmp_path: Path) -> None:
        # MED-4: host-unreachable evidence never reads as dormant
        unreachable = Observation(0, 0.0, "unreachable", "closed", ())
        context = make_context(SEAT_A_DEF, tmp_path, poller=FakePoller([unreachable]))
        assert context.poller.poll({}) is unreachable
        controller = controller_mod.SystemdUserController(context)
        controller._operation = "_stop_locked"
        assert controller._post_lock_poll() is False

    def test_idempotent_start_is_noop_success(self, tmp_path: Path) -> None:
        context = make_context(SEAT_A_DEF, tmp_path, poller=FakePoller([serving()]))
        outcome = controller_mod.SystemdUserController(context).start()
        # the post-lock poll saw the exact sole model: no-op success, and
        # the guard never received GO (operation argv stayed unset)
        assert outcome.state == "serving"
        assert FakeGuard.instances[-1].operation_argv is None


# --- BLK-6: parsers -----------------------------------------------------------


class TestParsers:
    def test_parse_systemctl_show_ok(self) -> None:
        show = parse_systemctl_show(
            "ActiveState=active\nSubState=running\nResult=success\nNRestarts=0\nRestart=no\n", 0
        )
        assert show["ActiveState"] == "active"
        assert show["NRestarts"] == "0"

    @pytest.mark.parametrize(
        "stdout",
        [
            "ActiveState=active\nSubState=running\nResult=success\nNRestarts=0\n",  # missing Restart
            "ActiveState=active\nActiveState=inactive\nSubState=running\nResult=success\nNRestarts=0\nRestart=no\n",
            "ActiveState active\nSubState=running\nResult=success\nNRestarts=0\nRestart=no\n",
            "ActiveState=active\nSubState=running\nResult=success\nNRestarts=x\nRestart=no\n",
            "ActiveState=active\nSubState=running\nResult=success\nNRestarts=0\nRestart=no\nExtra=1\n",
        ],
    )
    def test_parse_systemctl_show_invalid(self, stdout: str) -> None:
        with pytest.raises(InvalidSystemdState):
            parse_systemctl_show(stdout, 0)

    def test_parse_systemctl_show_nonzero_exit(self) -> None:
        with pytest.raises(InvalidSystemdState):
            parse_systemctl_show("ActiveState=failed\n", 1)

    def test_parse_systemctl_show_cap(self) -> None:
        with pytest.raises(InvalidSystemdState):
            parse_systemctl_show("SubState=" + "x" * 70_000 + "\n", 0)

    def test_status_exit_matrix(self) -> None:
        assert parse_status_exit(0) == "serving"
        assert parse_status_exit(1) == "dormant"
        assert parse_status_exit(2) == "error"
        assert parse_status_exit(None) == "indeterminate"

    def test_parse_pid_inspect(self) -> None:
        assert parse_pid_inspect("TESTUDO_PID_MATCH\n", 0) is True
        assert parse_pid_inspect("TESTUDO_PID_MATCH\nextra\n", 0) is False
        assert parse_pid_inspect("TESTUDO_PID_MATCH\n", 79) is False

    def test_parse_testudo_pid(self) -> None:
        line = "TESTUDO_PID 4242 4242 999999 8f4c1e2a-9b3d-4c5e-8f6a-7b8c9d0e1f2a " + "0" * 64
        fields = parse_testudo_pid(line + "\n")
        assert fields is not None
        assert fields["pid"] == "4242"
        assert fields["argv_sha256"] == "0" * 64

    @pytest.mark.parametrize(
        "line",
        [
            "TESTUDO_PID 4242 4243 999999 8f4c1e2a-9b3d-4c5e-8f6a-7b8c9d0e1f2a "
            + "0" * 64,  # pgid != pid
            "TESTUDO_PID 04242 4242 999999 8f4c1e2a-9b3d-4c5e-8f6a-7b8c9d0e1f2a "
            + "0" * 64,  # leading zero
            "TESTUDO_PID 4242 4242 999999 not-a-boot-id " + "0" * 64,
            "TESTUDO_PID 4242 4242 999999 8f4c1e2a-9b3d-4c5e-8f6a-7b8c9d0e1f2a " + "g" * 64,
            "",
        ],
    )
    def test_parse_testudo_pid_invalid(self, line: str) -> None:
        assert parse_testudo_pid(line) is None

    def test_parse_testudo_pid_rejects_extra_lines(self) -> None:
        good = "TESTUDO_PID 4242 4242 999999 8f4c1e2a-9b3d-4c5e-8f6a-7b8c9d0e1f2a " + "0" * 64
        assert parse_testudo_pid(good + "\nnoise\n") is None


# --- BLK-5: TESTUDO_PID persistence through the C start pipeline ---------------


class TestPidPersistence:
    def _state_store(self, tmp_path: Path) -> StateStore:
        return StateStore(tmp_path / "state.v1.json")

    def test_c_start_persists_pid_record_and_serves(self, tmp_path: Path) -> None:
        store = self._state_store(tmp_path)
        context = make_context(
            SEAT_C_DEF, tmp_path, poller=FakePoller([empty(), serving()]), state_store=store
        )
        outcome = controller_mod.BareCommandController(context).start()
        assert outcome.state == "serving"
        records = store.load()["pid_records"]
        assert len(records) == 1
        record = records[0]
        assert record["pid"] == 4242 and record["pgid"] == 4242
        assert record["seat_id"] == SEAT_C and record["host_id"] == HOST_ID
        assert record["argv_sha256"] == argv_sha256(SEAT_C_DEF["launch_argv"])

    def test_c_stop_uses_persisted_record(self, tmp_path: Path) -> None:
        store = self._state_store(tmp_path)
        context = make_context(
            SEAT_C_DEF, tmp_path, poller=FakePoller([empty(), serving()]), state_store=store
        )
        controller_mod.BareCommandController(context).start()
        stop_context = make_context(
            SEAT_C_DEF, tmp_path, poller=FakePoller([empty()]), state_store=store
        )
        outcome = controller_mod.BareCommandController(stop_context).stop()
        assert outcome.state == "dormant"
        argv = FakeGuard.instances[-1].operation_argv
        assert argv is not None and argv[2] == C_PID_V1
        assert argv[4:6] == ["stop", "4242"]

    def test_c_stop_without_record_refuses(self, tmp_path: Path) -> None:
        context = make_context(SEAT_C_DEF, tmp_path, poller=FakePoller([empty()]))
        with pytest.raises(controller_mod.SeatError, match="pid mismatch"):
            controller_mod.BareCommandController(context)._operation_argv("_stop_locked")

    def test_c_start_without_valid_pid_line_is_indeterminate(self, tmp_path: Path) -> None:
        store = self._state_store(tmp_path)
        context = make_context(
            SEAT_C_DEF, tmp_path, poller=FakePoller([empty()]), state_store=store
        )

        class NoPidGuard(FakeGuard):
            @staticmethod
            def _operation_output(argv: list[str]) -> str:
                return "launch produced no pid line\n"

        import testudo.seats.controller as cm

        monkey = pytest.MonkeyPatch()
        monkey.setattr(cm, "GuardController", NoPidGuard)
        try:
            outcome = controller_mod.BareCommandController(context).start()
        finally:
            monkey.undo()
        assert outcome.state == "indeterminate"
        assert store.load()["pid_records"] == []


# --- BLK-3: command-time consent drift -----------------------------------------


def _trusted_service(tmp_path: Path, seat: dict[str, Any]) -> tuple[SeatService, str]:
    service = SeatService(
        SeatStore(tmp_path / "seats.v1.json"),
        StateStore(tmp_path / "state.v1.json"),
        HostKeyTrustStore(tmp_path / "known_hosts"),
    )
    draft = service.draft_create(
        "host",
        {
            "label": "fixture",
            "ssh": {"kind": "explicit", "user": "fixture", "host": "127.0.0.1", "port": 2222},
            "transport": {"kind": "ssh-tunnel"},
        },
    )
    applied = service.config_apply(draft["draft_id"], draft["draft_revision"], 0)
    host_id = service.config_get()["hosts"][0]["id"]
    seat_fields = {key: value for key, value in seat.items() if key != "id"}
    seat_draft = service.draft_create("seat", seat_fields, parent_host_id=host_id)
    service.config_apply(
        seat_draft["draft_id"], seat_draft["draft_revision"], applied["config_revision"]
    )
    # trust the host: one known-hosts line carrying the fingerprint comment
    service.trust_store.install_initial(f"[127.0.0.1]:2222 ssh-ed25519 {'A' * 68} {FINGERPRINT}")
    return service, host_id


def _consent_service(
    tmp_path: Path,
    seat: dict[str, Any],
    *,
    linger: str = "yes",
    effective: EffectiveSsh = FAKE_EFFECTIVE,
) -> tuple[SeatService, str]:
    service, host_id = _trusted_service(tmp_path, seat)
    host = service.store.load()["hosts"][0]
    digest = consent_digest(
        host_config_excluding_consent={
            "id": host["id"],
            "label": host["label"],
            "ssh": host["ssh"],
            "transport": host["transport"],
            "seats": host["seats"],
        },
        ssh_effective=effective,
        trusted_host_key_fingerprint=FINGERPRINT,
        host_lifetime=linger,
        transport=host["transport"],
        ordered_seats=host["seats"],
    )
    service.store.mutate(
        service.store.load()["revision"],
        lambda c: c["hosts"][0].update(
            consent={
                "digest": digest,
                "accepted_at": "2026-09-15T00:00:00Z",
                "policy_version": 5,
                "ssh_effective_sha256": effective.sha256(),
                "host_key_fingerprint": FINGERPRINT,
            }
        ),
    )
    service.config_revision = service.store.load()["revision"]
    return service, host_id


@pytest.fixture
def wired_service(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_mod, "resolve_effective_ssh", lambda descriptor: FAKE_EFFECTIVE)
    monkeypatch.setattr(service_mod, "EndpointPoller", lambda: FakePoller([serving(), empty()]))


class TestCommandTimeDrift:
    def test_operate_succeeds_with_current_consent(
        self, tmp_path: Path, wired_service: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        service, _host = _consent_service(tmp_path, SEAT_A_DEF)
        monkeypatch.setattr(
            SeatService, "probe_linger", lambda self, d, e: LingerObservation("yes")
        )
        seat_id = service.config_get()["hosts"][0]["seats"][0]["id"]
        result = service.seat_operate(seat_id, "start")
        assert result["state"] == "serving"

    def test_ssh_drift_refuses(
        self, tmp_path: Path, wired_service: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        service, _host = _consent_service(tmp_path, SEAT_A_DEF)
        drifted = EffectiveSsh(
            (*FAKE_EFFECTIVE.ordered_pairs, ("identityfile", "/other/key")),
            FAKE_EFFECTIVE.binary_path,
            FAKE_EFFECTIVE.binary_version,
            FAKE_EFFECTIVE.binary_sha256,
        )
        monkeypatch.setattr(service_mod, "resolve_effective_ssh", lambda descriptor: drifted)
        monkeypatch.setattr(
            SeatService, "probe_linger", lambda self, d, e: LingerObservation("yes")
        )
        seat_id = service.config_get()["hosts"][0]["seats"][0]["id"]
        with pytest.raises(ApiError, match="drifted since consent"):
            service.seat_operate(seat_id, "start")

    def test_linger_drift_refuses(
        self, tmp_path: Path, wired_service: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        service, _host = _consent_service(tmp_path, SEAT_A_DEF, linger="yes")
        monkeypatch.setattr(SeatService, "probe_linger", lambda self, d, e: LingerObservation("no"))
        seat_id = service.config_get()["hosts"][0]["seats"][0]["id"]
        with pytest.raises(ApiError, match="digest drifted"):
            service.seat_operate(seat_id, "start")

    def test_fingerprint_drift_refuses(
        self, tmp_path: Path, wired_service: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        service, _host = _consent_service(tmp_path, SEAT_A_DEF)
        # a replacement key was trusted after consent was given
        service.trust_store.replace_for_host(
            f"[127.0.0.1]:2222 ssh-ed25519 {'B' * 68} SHA256:" + "B" * 43,
            "127.0.0.1",
            2222,
        )
        monkeypatch.setattr(
            SeatService, "probe_linger", lambda self, d, e: LingerObservation("yes")
        )
        seat_id = service.config_get()["hosts"][0]["seats"][0]["id"]
        with pytest.raises(ApiError, match="host key drifted"):
            service.seat_operate(seat_id, "start")

    def test_force_stop_challenge_binds_consent(
        self, tmp_path: Path, wired_service: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        service, _host = _consent_service(tmp_path, SEAT_A_DEF)
        monkeypatch.setattr(
            SeatService, "probe_linger", lambda self, d, e: LingerObservation("yes")
        )
        seat_id = service.config_get()["hosts"][0]["seats"][0]["id"]
        challenge = service.seat_force_stop_challenge(seat_id)
        confirmation = challenge["confirmation_id"]
        # consent changed after the challenge was issued: the stored digest
        # no longer matches, so the operation must refuse
        stored = service.force_stop_challenges[confirmation]
        stored.consent_digest = "f" * 64
        with pytest.raises(ApiError, match="valid force-stop challenge"):
            service.seat_operate(seat_id, "force-stop", confirmation)
