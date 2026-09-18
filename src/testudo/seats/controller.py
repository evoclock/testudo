# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Seat controllers: templates A (systemd user unit), B (control script),
and C (bare command) with the L3 ownership gate and per-endpoint
serialization.

Every destructive operation:
1. acquires the local lock (L1);
2. acquires the remote guard via GUARD_V1 (L2);
3. performs the final ownership/conflict poll while both locks are held (L3);
4. writes GO, runs the operation, reconciles readiness/stop while both
   locks remain held, and releases.
"""

from __future__ import annotations

import re
import time
from abc import ABC
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from testudo.seats._scripts import C_PID_V1, EXEC_V1, LAUNCH_V1, LOG_TAIL_V1
from testudo.seats.config import ConflictError, SeatStore, StateStore, validate_pid_record
from testudo.seats.guard import GuardController, GuardOutcome, LocalGuardError, LocalLock
from testudo.seats.lifetime import LingerObservation, start_gate
from testudo.seats.render import argv_sha256, lock_basename, lock_key, new_nonce, remote_command
from testudo.seats.sanitize import sanitize_for_display
from testudo.seats.ssh import ExecResult, SshDescriptor, exec_remote
from testudo.seats.transport import Observation

START_WINDOW_SECONDS = 1800.0
STOP_WINDOW_SECONDS = 30.0
RELEASE_GRACE_SECONDS = 30.0  # bounded RELEASE handshake after the window ends
READY_POLL_INTERVAL = 1.0
STOP_POLL_INTERVAL = 1.0
MIN_READY_TIMEOUT = 30
MAX_READY_TIMEOUT = 1800
SYSTEMD_SHOW_CAP_BYTES = 64 * 1024
SHOW_PROPERTIES = ("ActiveState", "SubState", "Result", "NRestarts", "Restart")
TRANSITIONAL_ACTIVE = frozenset({"activating", "reloading"})
STOPPING_ACTIVE = "deactivating"
TESTUDO_PID_RE = re.compile(
    r"^TESTUDO_PID ([0-9]{1,10}) ([0-9]{1,10}) ([0-9]{1,10})"
    r" ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}) ([0-9a-f]{64})$"
)


@dataclass
class OperationOutcome:
    """The controller-side result of one operation."""

    state: str  # serving | dormant | error | indeterminate | refused
    error: str | None = None
    detail: str = ""
    occupant_models: tuple[str, ...] = ()
    log_tail: str | None = None


class SeatError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class InvalidSystemdState(SeatError):
    """`systemctl show` output was missing, duplicate, or malformed (A1)."""


@dataclass
class Reconciliation:
    """The result of the in-guard readiness/stop reconciliation (A1/A2/B1/C4)."""

    state: str  # serving | dormant | error | indeterminate
    error: str | None = None
    detail: str = ""
    occupant_models: tuple[str, ...] = ()
    log_tail: str | None = None


@dataclass
class SeatContext:
    """Everything the controller needs for one seat, resolved server-side."""

    host_id: str
    seat_id: str
    seat: dict[str, Any]
    descriptor: SshDescriptor
    endpoint_host: str
    endpoint_port: int
    ssh_hostname: str
    ssh_port: int
    config_revision: int
    poller: Any  # EndpointPoller
    linger: LingerObservation
    stores: SeatStore | None = None
    state_store: StateStore | None = None
    transport: dict[str, Any] | None = None
    executor: Callable[[str], ExecResult] | None = None

    def run_remote(self, remote: str) -> ExecResult | None:
        """Run one read-only remote command (EXEC_V1 wrapped) if an
        executor is wired; None means no execution path is available."""
        if self.executor is None:
            return None
        return self.executor(remote)


# --- parsers (BLK-6) ---------------------------------------------------------


def parse_systemctl_show(stdout: str, exit_code: int | None) -> dict[str, str]:
    """A1 strict `systemctl show` parser: exactly one line for each
    requested key; missing, duplicate, malformed, unexpected keys, or a
    nonzero exit is `invalid-systemd-state`. Output is capped at 64 KiB."""
    if exit_code != 0:
        raise InvalidSystemdState("systemctl show exited nonzero")
    if len(stdout.encode("utf-8")) > SYSTEMD_SHOW_CAP_BYTES:
        raise InvalidSystemdState("systemctl show output exceeds 64 KiB")
    props: dict[str, str] = {}
    for line in stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in SHOW_PROPERTIES:
            raise InvalidSystemdState(f"malformed show line: {line!r}")
        if key in props:
            raise InvalidSystemdState(f"duplicate key {key}")
        props[key] = value
    for key in SHOW_PROPERTIES:
        if key not in props:
            raise InvalidSystemdState(f"missing key {key}")
    if not re.fullmatch(r"[0-9]+", props["NRestarts"]):
        raise InvalidSystemdState("NRestarts is not a decimal integer")
    return props


def systemd_state(show: dict[str, str]) -> str:
    """Derive the unit lifecycle state from a parsed show (A1)."""
    active = show["ActiveState"]
    if active == "failed":
        return "error"
    if show["Result"] not in {"", "success"}:
        return "error"
    if active == "inactive":
        return "dormant"
    if active == STOPPING_ACTIVE:
        return "stopping"
    if active in TRANSITIONAL_ACTIVE:
        return "starting"
    if active == "active":
        sub = show["SubState"]
        if sub in {"activating", "reloading", "auto-restart"}:
            return "starting"
        return "serving-candidate"  # active with a non-transitional SubState
    raise InvalidSystemdState(f"unknown ActiveState {active}")


def parse_status_exit(exit_code: int | None) -> str:
    """B1 status exit-code matrix: 0 = serving, 1 = dormant, every other
    code = error; a lost local SSH (None) is indeterminate."""
    if exit_code is None:
        return "indeterminate"
    if exit_code == 0:
        return "serving"
    if exit_code == 1:
        return "dormant"
    return "error"


def parse_pid_inspect(stdout: str, exit_code: int | None) -> bool:
    """C_PID_V1 inspect parsing: exactly one ``TESTUDO_PID_MATCH`` line and
    exit 0 proves the persisted PID identity still matches."""
    lines = [line for line in stdout.splitlines() if line.strip()]
    return exit_code == 0 and lines == ["TESTUDO_PID_MATCH"]


def parse_testudo_pid(stdout: str) -> dict[str, str] | None:
    """Exactly one ASCII ``TESTUDO_PID <pid> <pgid> <ticks> <boot> <hash>``
    line (C3); anything else is None and the launch is indeterminate."""
    lines = [line for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        return None
    match = TESTUDO_PID_RE.match(lines[0])
    if match is None:
        return None
    pid, pgid, ticks, boot, digest = match.groups()
    if pid.startswith("0") or pgid != pid or ticks.startswith("0"):
        return None  # no leading zeros; pgid must equal pid (setsid leader)
    return {
        "pid": pid,
        "pgid": pgid,
        "proc_start_ticks": ticks,
        "boot_id": boot,
        "argv_sha256": digest,
    }


class SeatController(ABC):
    """Base class implementing the guarded destructive-operation pipeline."""

    template: str

    def __init__(self, context: SeatContext) -> None:
        self.context = context
        self._operation: str | None = None
        self._gate_noop = False
        self._gate_refusal_error = "ownership gate refused"
        self._baseline_restarts: int | None = None
        self._last_restarts: int | None = None
        self._reconciliation: Reconciliation | None = None
        self._window_deadline = 0.0

    # --- public operations ---------------------------------------------------

    def start(self) -> OperationOutcome:
        # U1: the immediately refreshed linger value gates start.
        allowed, warning = start_gate(self.context.linger)
        if not allowed:
            return OperationOutcome(
                "refused", error="host lifetime prerequisite", detail=warning or ""
            )
        return self._start_locked()

    def stop(self) -> OperationOutcome:
        return self._stop_locked()

    def force_stop(self) -> OperationOutcome:
        return self._force_stop_locked()

    def inspect(self) -> dict[str, Any]:
        """Read-only inspect: no lock, no guard."""
        raise NotImplementedError

    def diagnostics(self) -> str:
        raise NotImplementedError

    # --- the guarded pipelines (BLK-1) ---------------------------------------

    def _start_locked(self) -> OperationOutcome:
        """Template start under the full guarded pipeline."""
        return self._run_guarded("_start_locked", window=self._ready_timeout())

    def _stop_locked(self) -> OperationOutcome:
        return self._run_guarded("_stop_locked", window=STOP_WINDOW_SECONDS)

    def _force_stop_locked(self) -> OperationOutcome:
        return self._run_guarded("_force_stop_locked", window=STOP_WINDOW_SECONDS)

    def _run_guarded(self, name: str, *, window: float) -> OperationOutcome:
        """L1 -> L2 -> L3 poll -> GO -> operation -> reconcile -> RELEASE."""
        self._operation = name
        self._gate_noop = False
        self._reconciliation = None
        self._baseline_restarts = (
            self._read_baseline_restarts() if name == "_start_locked" else None
        )
        self._last_restarts = self._baseline_restarts
        self._window_deadline = time.monotonic() + window
        lock = self._lock()
        try:
            lock.acquire()
        except LocalGuardError as exc:
            if "contention timeout" in str(exc):
                return OperationOutcome("refused", error="operation in progress")
            return OperationOutcome("refused", error="local guard unavailable")
        try:
            nonce = new_nonce()
            basename = lock_basename(
                lock_key(
                    self.context.ssh_hostname,
                    self.context.ssh_port,
                    self.context.endpoint_host,
                    self.context.endpoint_port,
                )
            )
            controller = GuardController(
                self.context.descriptor,
                basename,
                nonce,
                poll_permits=self._post_lock_poll,
                reconcile=self._reconcile_operation,
            )
            outcome = controller.operate(
                self._operation_argv(name),
                timeout=window + RELEASE_GRACE_SECONDS,
            )
            return self._finalize(name, outcome)
        finally:
            lock.release()

    # --- internals -----------------------------------------------------------

    def _ready_timeout(self) -> float:
        return float(self.context.seat["ready_timeout"])

    def _lock(self) -> LocalLock:
        key = lock_key(
            self.context.ssh_hostname,
            self.context.ssh_port,
            self.context.endpoint_host,
            self.context.endpoint_port,
        )
        return LocalLock(_local_lock_path(key))

    def _post_lock_poll(self) -> bool:
        """L3: the final endpoint ownership/conflict poll while both locks
        are held. Start permits an empty endpoint or the exact sole model
        (the sole-model case is a no-op success that never runs GO); B stop
        requires the exact sole model; A/C stop proceed when no
        different/additional model is reported."""
        observation: Observation | None = self._poll_now()
        if observation is None:
            return False
        if observation.host_state != "reachable":
            return False  # host-unreachable evidence refuses (MED-4)
        if observation.endpoint_state in {"invalid", "unauthorized", "tls-error", "indeterminate"}:
            return False  # unavailable/invalid/unauthorized/TLS/stale evidence refuses
        models = set(observation.models)
        exact = self.context.seat["model_id"]
        if self._operation == "_start_locked":
            if models == {exact}:
                # L3: idempotent start — the exact sole model is already
                # reported, so the operation is a no-op success.
                self._gate_noop = True
                return False
            return not models  # different/additional models refuse
        if (
            self._operation in {"_stop_locked", "_force_stop_locked"}
            and self.template == "control-script"
        ):
            return models == {exact}  # B stop: exact sole model only (B1/B3)
        return not models or models == {exact}

    def _reconcile_operation(self, operation_output: str) -> None:
        """Readiness/stop reconciliation while both locks remain held."""
        if self._operation == "_start_locked":
            self._reconcile_start(operation_output)
        else:
            self._reconcile_stop()

    # --- endpoint helpers ----------------------------------------------------

    def _poll_now(self) -> Observation | None:
        try:
            observation: Observation = self.context.poller.poll(
                self.context.transport or {"kind": self._transport_kind()},
                self.context.endpoint_host,
                self.context.endpoint_port,
                self.context.seat["model_id"],
                descriptor=self.context.descriptor,
            )
        except Exception:
            return None
        return observation

    def _sole_model_observation(self) -> tuple[bool, tuple[str, ...]]:
        """One poll: (is the exact model the sole reported model, models)."""
        observation = self._poll_now()
        if observation is None or observation.host_state != "reachable":
            return False, ()
        models = tuple(observation.models)
        return set(models) == {self.context.seat["model_id"]}, models

    def _transport_kind(self) -> str:
        return "ssh-tunnel"

    def _operation_argv(self, name: str) -> list[str]:
        raise NotImplementedError

    def _read_baseline_restarts(self) -> int | None:
        return None

    # --- generic reconciliation loops (BLK-6) --------------------------------

    def _reconcile_start(self, operation_output: str) -> None:
        """Default readiness loop: the exact sole model on a fresh endpoint
        poll, until the readiness window ends."""
        self._reconciliation = self._await_sole_model(deadline=self._window_deadline)

    def _await_sole_model(self, *, deadline: float) -> Reconciliation:
        while time.monotonic() < deadline:
            is_sole, models = self._sole_model_observation()
            if is_sole:
                return Reconciliation("serving", occupant_models=models)
            time.sleep(READY_POLL_INTERVAL)
        return Reconciliation(
            "error",
            error="readiness-timeout",
            detail="the process may still be running; stop remains available; "
            "actual survival remains subject to U1 and host policy",
        )

    def _reconcile_stop(self) -> None:
        """Default stop confirmation: the endpoint no longer reports the
        seat model within the stop window (A2/B1/C3)."""
        while time.monotonic() < self._window_deadline:
            _is_sole, models = self._sole_model_observation()
            if self.context.seat["model_id"] not in models:
                self._reconciliation = Reconciliation("dormant")
                return
            time.sleep(STOP_POLL_INTERVAL)
        self._reconciliation = Reconciliation("indeterminate", detail="stop window elapsed")

    # --- outcome interpretation ----------------------------------------------

    def _finalize(self, name: str, outcome: GuardOutcome) -> OperationOutcome:
        if outcome.exit_code is None:
            return OperationOutcome(
                "indeterminate",
                detail="local SSH terminated; the remote command may still be running",
            )
        if outcome.refused_reason == "BUSY":
            return OperationOutcome("refused", error="operation in progress")
        if outcome.refused_reason in {"GATE_REFUSED", "GATE_TIMEOUT"}:
            if self._gate_noop:
                # L3 idempotent start: the exact sole model was already
                # reported before GO, so this is a no-op success.
                return OperationOutcome("serving", occupant_models=(self.context.seat["model_id"],))
            return OperationOutcome("refused", error=self._gate_refusal_error)
        if outcome.refused_reason in {"UNAVAILABLE", "UNSAFE"}:
            return OperationOutcome("refused", error="guard unavailable")
        if outcome.rc_trailer is None:
            return OperationOutcome("indeterminate", detail="malformed guard protocol")
        if outcome.rc_trailer != 0:
            return self._remote_error(name, outcome)
        # the guarded SSH command closed normally; reconcile decided
        return self._final_state(name, outcome)

    def _remote_error(self, name: str, outcome: GuardOutcome) -> OperationOutcome:
        return OperationOutcome("error", error=f"remote exit {outcome.rc_trailer}")

    def _final_state(self, name: str, outcome: GuardOutcome) -> OperationOutcome:
        reconciliation = self._reconciliation or Reconciliation("indeterminate")
        if name == "_start_locked" and reconciliation.state == "serving":
            # the guarded SSH command closed normally; a fresh post-session
            # endpoint poll must still report the exact sole model (U1)
            is_sole, models = self._sole_model_observation()
            if not is_sole:
                return OperationOutcome(
                    "indeterminate",
                    detail="post-session endpoint poll does not confirm serving",
                )
            return OperationOutcome("serving", occupant_models=models)
        return OperationOutcome(
            reconciliation.state,
            error=reconciliation.error,
            detail=reconciliation.detail,
            occupant_models=reconciliation.occupant_models,
            log_tail=reconciliation.log_tail,
        )


def _local_lock_path(key_hex: str) -> Any:
    from pathlib import Path

    from testudo.seats.runtime_dirs import state_dir

    return Path(state_dir()) / "locks" / f"endpoint-{key_hex}.lock"


class SystemdUserController(SeatController):
    """Template A (A1/A2)."""

    template = "systemd-user"

    def _operation_argv(self, name: str) -> list[str]:
        unit = self.context.seat["unit"]
        if name == "_start_locked":
            return ["systemctl", "--user", "start", "--", unit]
        if name == "_stop_locked":
            return ["systemctl", "--user", "stop", "--", unit]
        if name == "_force_stop_locked":
            return ["systemctl", "--user", "kill", "--signal=SIGKILL", "--", unit]
        raise SeatError(f"unknown operation {name}")

    def inspect(self) -> dict[str, Any]:
        unit = self.context.seat["unit"]
        argv = [
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
            unit,
        ]
        result: dict[str, Any] = {"argv": argv, "remote": remote_command(EXEC_V1, argv)}
        executed = self.context.run_remote(result["remote"])
        if executed is not None:
            try:
                show = parse_systemctl_show(executed.stdout, executed.exit_code)
            except InvalidSystemdState as exc:
                result["state"] = {"error": "invalid-systemd-state", "detail": str(exc)}
                return result
            result["state"] = {
                "active_state": show["ActiveState"],
                "sub_state": show["SubState"],
                "result": show["Result"],
                "n_restarts": int(show["NRestarts"]),
                "restart": show["Restart"],
            }
        return result

    def diagnostics(self) -> str:
        unit = self.context.seat["unit"]
        argv = ["systemctl", "--user", "status", "--no-pager", "--lines=10", "--", unit]
        return remote_command(EXEC_V1, argv)

    # --- A1/A2 readiness and stop reconciliation ------------------------------

    def _read_baseline_restarts(self) -> int | None:
        """Record the inspect baseline before start (A1)."""
        show = self._show_now()
        return None if show is None else int(show["NRestarts"])

    def _show_now(self) -> dict[str, str] | None:
        unit = self.context.seat["unit"]
        argv = [
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
            unit,
        ]
        executed = self.context.run_remote(remote_command(EXEC_V1, argv))
        if executed is None:
            return None
        try:
            return parse_systemctl_show(executed.stdout, executed.exit_code)
        except InvalidSystemdState:
            return None

    def _check_restart_counter(self, show: dict[str, str]) -> Reconciliation | None:
        """A1: any NRestarts increase from the baseline or between two
        starting observations is `restart-loop`; a decrease causes a new
        baseline and an indeterminate observation."""
        restarts = int(show["NRestarts"])
        if self._baseline_restarts is not None and restarts > self._baseline_restarts:
            return Reconciliation("error", error="restart-loop")
        if self._last_restarts is not None:
            if restarts > self._last_restarts:
                return Reconciliation("error", error="restart-loop")
            if restarts < self._last_restarts:
                self._baseline_restarts = restarts  # new baseline (unit manager restarted)
                return Reconciliation(
                    "indeterminate", detail="NRestarts decreased; unit manager likely restarted"
                )
        self._last_restarts = restarts
        return None

    def _reconcile_start(self, operation_output: str) -> None:
        """A1 readiness: activating/reloading continues polling; active with
        a non-transitional SubState plus the exact sole endpoint model is
        serving; failed/non-success Result is error; deactivating means
        stopping; inactive means dormant."""
        while time.monotonic() < self._window_deadline:
            show = self._show_now()
            if show is None:
                self._reconciliation = Reconciliation(
                    "indeterminate", detail="invalid-systemd-state"
                )
                return
            counter = self._check_restart_counter(show)
            if counter is not None:
                self._reconciliation = counter
                return
            state = systemd_state(show)
            if state == "starting":
                time.sleep(READY_POLL_INTERVAL)
                continue
            if state == "stopping":
                self._reconciliation = Reconciliation("dormant", detail="deactivating")
                return
            if state == "dormant":
                self._reconciliation = Reconciliation("dormant")
                return
            if state == "error":
                self._reconciliation = Reconciliation(
                    "error", error="unit failed", detail=f"Result={show['Result']}"
                )
                return
            # active with a non-transitional SubState: require endpoint proof
            self._reconciliation = self._await_sole_model(deadline=self._window_deadline)
            return
        self._reconciliation = Reconciliation("error", error="readiness-timeout")

    def _reconcile_stop(self) -> None:
        """A2: poll inspect until ActiveState=inactive|failed and the
        endpoint no longer reports the seat model, at most 30 seconds."""
        while time.monotonic() < self._window_deadline:
            show = self._show_now()
            if show is None:
                self._reconciliation = Reconciliation(
                    "indeterminate", detail="invalid-systemd-state"
                )
                return
            if show["ActiveState"] in {"inactive", "failed"} and (
                self.context.seat["model_id"] not in self._recent_models()
            ):
                self._reconciliation = Reconciliation("dormant")
                return
            time.sleep(STOP_POLL_INTERVAL)
        self._reconciliation = Reconciliation(
            "indeterminate", detail="stop window elapsed before inactive and model gone"
        )

    def _recent_models(self) -> set[str]:
        observation = self._poll_now()
        if observation is None:
            return set()
        return set(observation.models)


class ControlScriptController(SeatController):
    """Template B (B1-B3). No Testudo-side force-stop."""

    template = "control-script"

    def __init__(self, context: SeatContext) -> None:
        super().__init__(context)
        self._gate_refusal_error = "host-side intervention required"

    def _operation_argv(self, name: str) -> list[str]:
        script = self.context.seat["script"]
        if name == "_start_locked":
            return [script, self.context.seat.get("start_subcommand", "start")]
        if name == "_stop_locked":
            return [script, self.context.seat.get("stop_subcommand", "stop")]
        raise SeatError("unsupported: host-side intervention required")

    def force_stop(self) -> OperationOutcome:
        # B3: no challenge, no force-stop.
        return OperationOutcome("refused", error="unsupported: host-side intervention required")

    def status_argv(self) -> list[str]:
        return [
            self.context.seat["script"],
            self.context.seat.get("status_subcommand", "status"),
        ]

    def inspect(self) -> dict[str, Any]:
        remote = remote_command(EXEC_V1, self.status_argv())
        result: dict[str, Any] = {"argv": self.status_argv(), "remote": remote}
        executed = self.context.run_remote(remote)
        if executed is not None:
            result["state"] = {
                "status": parse_status_exit(executed.exit_code),
                "exit_code": executed.exit_code,
            }
        return result

    # --- B1 readiness --------------------------------------------------------

    def _status_now(self) -> str | None:
        executed = self.context.run_remote(remote_command(EXEC_V1, self.status_argv()))
        if executed is None:
            return None
        return parse_status_exit(executed.exit_code)

    def _reconcile_start(self, operation_output: str) -> None:
        """B1: a status claim is never sufficient; serving additionally
        requires a fresh endpoint poll reporting only the exact model."""
        while time.monotonic() < self._window_deadline:
            status = self._status_now()
            if status == "error":
                self._reconciliation = Reconciliation(
                    "error", error="status exit error", detail="control script reported an error"
                )
                return
            if status == "indeterminate":
                self._reconciliation = Reconciliation(
                    "indeterminate", detail="status poll lost the local SSH process"
                )
                return
            if status == "serving":
                self._reconciliation = self._await_sole_model(deadline=self._window_deadline)
                return
            # dormant: keep polling within the readiness window
            time.sleep(READY_POLL_INTERVAL)
        self._reconciliation = Reconciliation("error", error="readiness-timeout")


class BareCommandController(SeatController):
    """Template C (C3/C4)."""

    template = "bare-command"

    def launch_remote(self) -> str:
        seat = self.context.seat
        key = lock_key(
            self.context.ssh_hostname,
            self.context.ssh_port,
            self.context.endpoint_host,
            self.context.endpoint_port,
        )
        expected = argv_sha256(seat["launch_argv"])
        args = [
            lock_basename(key),
            new_nonce(),  # replaced by the real nonce in _run_guarded
            "sh",
            "-c",
            LAUNCH_V1,
            "testudo",
            seat["cwd"],
            self.context.seat_id,
            expected,
            *seat["launch_argv"],
        ]
        return remote_command("GUARD", args)

    def _operation_argv(self, name: str) -> list[str]:
        seat = self.context.seat
        if name == "_start_locked":
            expected = argv_sha256(seat["launch_argv"])
            return [
                "sh",
                "-c",
                LAUNCH_V1,
                "testudo",
                seat["cwd"],
                self.context.seat_id,
                expected,
                *seat["launch_argv"],
            ]
        if name in {"_stop_locked", "_force_stop_locked"}:
            record = self._pid_record()
            if record is None:
                raise SeatError("pid mismatch or reuse")
            # C3/C4: force-stop is the same identity-checked stop sequence.
            return [
                "sh",
                "-c",
                C_PID_V1,
                "testudo",
                "stop",
                str(record["pid"]),
                str(record["pgid"]),
                str(record["proc_start_ticks"]),
                record["boot_id"],
                record["argv_sha256"],
            ]
        raise SeatError(f"unknown operation {name}")

    # --- C3 PID records (BLK-5) ----------------------------------------------

    def _pid_record(self) -> dict[str, Any] | None:
        if self.context.state_store is None:
            return None
        state: dict[str, Any] = self.context.state_store.load()
        records: list[dict[str, Any]] = state["pid_records"]
        for record in records:
            if (
                record["seat_id"] == self.context.seat_id
                and record["host_id"] == self.context.host_id
            ):
                matched: dict[str, Any] = record
                return matched
        return None

    def _persist_pid_record(self, fields: dict[str, str]) -> bool:
        """C3: write the PID record atomically, only from the exact
        validated TESTUDO_PID result (P4 validation via the state store)."""
        store = self.context.state_store
        if store is None:
            return False
        record = {
            "host_id": self.context.host_id,
            "seat_id": self.context.seat_id,
            "ssh_hostname": self.context.ssh_hostname,
            "ssh_port": self.context.ssh_port,
            "endpoint_host": self.context.endpoint_host,
            "endpoint_port": self.context.endpoint_port,
            "pid": int(fields["pid"]),
            "pgid": int(fields["pgid"]),
            "proc_start_ticks": int(fields["proc_start_ticks"]),
            "boot_id": fields["boot_id"],
            "argv_sha256": fields["argv_sha256"],
        }
        validate_pid_record("pid-record", record)  # never persist an invalid record

        def mutation(state: dict[str, Any]) -> None:
            kept = [
                existing
                for existing in state["pid_records"]
                if not (
                    existing["seat_id"] == self.context.seat_id
                    and existing["host_id"] == self.context.host_id
                )
            ]
            kept.append(record)
            state["pid_records"] = kept

        for _ in range(3):  # bounded retry on revision conflict
            current = store.load()
            try:
                store.mutate(current["revision"], mutation)
                return True
            except ConflictError:
                continue
        return False

    # --- C3/C4 reconciliation --------------------------------------------------

    def _reconcile_start(self, operation_output: str) -> None:
        """C3: capture the exact TESTUDO_PID line from the launch output,
        persist the PID record, then await endpoint readiness (C4)."""
        fields = parse_testudo_pid(operation_output)
        if fields is None:
            # the guarded command closed normally but produced no validated
            # PID line: indeterminate, never a fabricated record
            self._reconciliation = Reconciliation(
                "indeterminate", detail="no validated TESTUDO_PID line in launch output"
            )
            return
        persisted = self._persist_pid_record(fields)
        if not persisted:
            self._reconciliation = Reconciliation(
                "indeterminate", detail="PID record could not be persisted"
            )
            return
        self._reconciliation = self._await_sole_model(deadline=self._window_deadline)

    def _reconcile_stop(self) -> None:
        """C_PID_V1 exit 0 already proved the identity-checked
        TERM/wait/KILL completed; confirm the endpoint no longer reports
        the model."""
        super()._reconcile_stop()

    def _remote_error(self, name: str, outcome: GuardOutcome) -> OperationOutcome:
        rc = outcome.rc_trailer
        if name in {"_stop_locked", "_force_stop_locked"} and rc == 79:
            return OperationOutcome("error", error="pid mismatch or reuse")
        if name == "_start_locked" and rc == 78:
            # C4: immediate exit is error: early-exit with a bounded
            # sanitized log tail
            return OperationOutcome("error", error="early-exit", log_tail=self._log_tail())
        return super()._remote_error(name, outcome)

    def _log_tail(self) -> str | None:
        executed = self.context.run_remote(self.log_tail_remote())
        if executed is None:
            return None
        return sanitize_for_display(executed.stdout)

    def inspect(self) -> dict[str, Any]:
        record = self._pid_record()
        if record is None:
            return {"pid_record": None}
        argv = [
            "inspect",
            str(record["pid"]),
            str(record["pgid"]),
            str(record["proc_start_ticks"]),
            record["boot_id"],
            record["argv_sha256"],
        ]
        result: dict[str, Any] = {"pid_record": record, "remote": remote_command(C_PID_V1, argv)}
        executed = self.context.run_remote(result["remote"])
        if executed is not None:
            result["state"] = {"matched": parse_pid_inspect(executed.stdout, executed.exit_code)}
        return result

    def log_tail_remote(self) -> str:
        return remote_command(LOG_TAIL_V1, [self.context.seat_id])


def controller_for(context: SeatContext) -> SeatController:
    template = context.seat["template"]
    if template == "systemd-user":
        return SystemdUserController(context)
    if template == "control-script":
        return ControlScriptController(context)
    if template == "bare-command":
        return BareCommandController(context)
    raise SeatError(f"unknown template {template}")


def make_executor(
    descriptor: SshDescriptor, *, timeout: float = 30.0
) -> Callable[[str], ExecResult]:
    """One read-only remote-command executor bound to a descriptor."""

    def execute(remote: str) -> ExecResult:
        return exec_remote(descriptor, remote, timeout=timeout)

    return execute
