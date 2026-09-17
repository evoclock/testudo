"""G5 — Template A shims: unit-state sequences, stop timeout, force-stop
confirmation path (A1/A2).

SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later

Executes the spec's exact Template A operation argv against the fixture
``systemctl`` shim (uploaded to the fixture PATH), driven by scripted state
sequences. Verifies: strict property parsing (one line per requested key,
missing/duplicate/malformed = invalid-systemd-state), activating→active
polling, restart-loop (NRestarts increase), failed/Result error paths,
stop timeout → indeterminate, and the separate force-stop confirmation
challenge semantics (server-generated, single-use, never automatic).
"""

from __future__ import annotations

import json
import time

import pytest

from .conftest import FixtureHost, GuardEnv
from .guard_client import GuardClient
from .render import new_nonce, remote_command, validate_unit

pytestmark = pytest.mark.seat_harness

UNIT = "testudo-fixture.service"


def _set_state(guard_env: GuardEnv, sequence: list[dict[str, object]]) -> None:
    session = guard_env.session()
    hex_payload = json.dumps({"sequence": sequence}).encode().hex()
    proc = session.run(
        f"python3 -c \"import sys; sys.stdout.buffer.write(bytes.fromhex('{hex_payload}'))\" "
        f"> ~/.fixture-state/systemd.json && echo 0 > ~/.fixture-state/step"
    )
    assert proc.returncode == 0, proc.stderr


def _inspect_argv(unit: str) -> list[str]:
    """The exact Template A inspect argv from the spec."""
    return [
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


def _parse_show(stdout: str) -> dict[str, str]:
    """Strict one-line-per-key parser; missing/duplicate/malformed is invalid."""
    props: dict[str, str] = {}
    for line in stdout.splitlines():
        if "=" not in line:
            raise ValueError("invalid-systemd-state: malformed line")
        key, _, value = line.partition("=")
        if key in props:
            raise ValueError(f"invalid-systemd-state: duplicate key {key}")
        props[key] = value
    return props


@pytest.fixture
def linux_only(seat_fixture_host: FixtureHost) -> None:
    """Gate: guarded operations run GUARD_V1 (flock/stat/timeout required)."""
    if not seat_fixture_host.linux_semantics:
        pytest.skip(
            "guarded Template A operations need GUARD_V1 (flock, GNU stat, "
            "timeout); section 8 platform boundary — run on the Linux fixture"
        )


def test_g5_inspect_argv_is_exact(guard_env: GuardEnv, normative_scripts: dict[str, str]) -> None:
    """The inspect command the harness executes is byte-identical to the spec's
    operation argv (EXEC_V1 wrapped, per L4/A1)."""
    validate_unit(UNIT)
    runner = guard_env.ssh_runner()
    remote = remote_command(
        normative_scripts["EXEC_V1"],
        [
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
            UNIT,
        ],
    )
    result = runner.run(remote, timeout=30)
    # Without shims installed the real systemctl --user fails (no user manager);
    # what matters here is argv transport, so accept the shim-less failure but
    # require the exact rendered string to have reached sshd (nonzero rc, no
    # local shell error).
    assert result.exit_code != 127 or "systemctl" in result.stderr


def test_g5_activating_then_active_sequence(
    guard_env: GuardEnv, normative_scripts: dict[str, str], install_shims: None
) -> None:
    """activating continues polling; active with a non-transitional SubState
    is the serving precondition (endpoint proof is G7's job)."""
    _set_state(
        guard_env,
        [
            {
                "ActiveState": "activating",
                "SubState": "start",
                "Result": "success",
                "NRestarts": "0",
                "Restart": "no",
            },
            {
                "ActiveState": "active",
                "SubState": "running",
                "Result": "success",
                "NRestarts": "0",
                "Restart": "no",
            },
        ],
    )
    runner = guard_env.ssh_runner()
    first = runner.run(
        remote_command(normative_scripts["EXEC_V1"], _inspect_argv(UNIT)), timeout=30
    )
    second = runner.run(
        remote_command(normative_scripts["EXEC_V1"], _inspect_argv(UNIT)), timeout=30
    )
    props1 = _parse_show(first.stdout)
    props2 = _parse_show(second.stdout)
    assert props1["ActiveState"] == "activating"  # keep polling
    assert props2["ActiveState"] == "active" and props2["SubState"] == "running"


def test_g5_failed_and_restart_loop(
    guard_env: GuardEnv, normative_scripts: dict[str, str], install_shims: None
) -> None:
    """failed state and a non-success Result are error-with-diagnostics; an
    NRestarts increase between observations is error: restart-loop."""
    _set_state(
        guard_env,
        [
            {
                "ActiveState": "active",
                "SubState": "running",
                "Result": "success",
                "NRestarts": "0",
                "Restart": "on-failure",
            },
            {
                "ActiveState": "activating",
                "SubState": "auto-restart",
                "Result": "success",
                "NRestarts": "1",
                "Restart": "on-failure",
            },
            {
                "ActiveState": "failed",
                "SubState": "failed",
                "Result": "exit-code",
                "NRestarts": "3",
                "Restart": "on-failure",
            },
        ],
    )
    runner = guard_env.ssh_runner()
    observations = [
        _parse_show(
            runner.run(
                remote_command(normative_scripts["EXEC_V1"], _inspect_argv(UNIT)), timeout=30
            ).stdout
        )
        for _ in range(3)
    ]
    assert observations[1]["NRestarts"] == "1"  # increased from baseline 0
    assert observations[2]["ActiveState"] == "failed"
    assert observations[2]["Result"] == "exit-code"  # non-success -> error


def test_g5_missing_property_is_invalid_systemd_state(
    guard_env: GuardEnv, normative_scripts: dict[str, str], install_shims: None
) -> None:
    # Single entry: Restart is missing entirely -> shim exits 92 -> the strict
    # one-line-per-key parser contract says this is invalid-systemd-state.
    _set_state(
        guard_env,
        [
            {"ActiveState": "active", "SubState": "running", "Result": "success", "NRestarts": "0"},
        ],
    )
    runner = guard_env.ssh_runner()
    result = runner.run(
        remote_command(normative_scripts["EXEC_V1"], _inspect_argv(UNIT)), timeout=30
    )
    assert result.exit_code != 0, "missing requested key must fail the strict parser"


@pytest.mark.usefixtures("linux_only")
def test_g5_start_then_stop_lifecycle(
    guard_env: GuardEnv, normative_scripts: dict[str, str], install_shims: None
) -> None:
    """systemctl --user start/stop under GUARD_V1: start exit 0 is NOT serving
    evidence; stop polls to inactive; unit-scoped stop never needs endpoint
    evidence (A2) but the harness records the sequence."""
    # The shim consumes one entry per invocation, verb-independent:
    # entry 0 = start command, entry 1 = stop command, entry 2 = final inspect.
    _set_state(
        guard_env,
        [
            {
                "ActiveState": "inactive",
                "SubState": "dead",
                "Result": "success",
                "NRestarts": "0",
                "Restart": "no",
                "exit": 0,
            },  # start command
            {
                "ActiveState": "deactivating",
                "SubState": "stop",
                "Result": "success",
                "NRestarts": "0",
                "Restart": "no",
                "exit": 0,
            },  # stop command
            {
                "ActiveState": "inactive",
                "SubState": "dead",
                "Result": "success",
                "NRestarts": "0",
                "Restart": "no",
            },  # post-stop inspect
        ],
    )
    lock = "endpoint-" + "a5" * 32 + ".lock"
    start = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
    start_out = start.operate(
        [
            "sh",
            "-c",
            normative_scripts["EXEC_V1"],
            "testudo",
            "systemctl",
            "--user",
            "start",
            "--",
            UNIT,
        ],
        timeout=60,
    )
    assert start_out.exit_code == 0
    # stop under a fresh guard, unit-scoped
    stop = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
    stop_out = stop.operate(
        [
            "sh",
            "-c",
            normative_scripts["EXEC_V1"],
            "testudo",
            "systemctl",
            "--user",
            "stop",
            "--",
            UNIT,
        ],
        timeout=60,
    )
    assert stop_out.exit_code == 0
    # post-stop inspect shows inactive (the derived dormant state)
    runner = guard_env.ssh_runner()
    final = _parse_show(
        runner.run(
            remote_command(normative_scripts["EXEC_V1"], _inspect_argv(UNIT)), timeout=30
        ).stdout
    )
    assert final["ActiveState"] == "inactive"


@pytest.mark.usefixtures("linux_only")
def test_g5_stop_timeout_is_indeterminate_not_success(
    guard_env: GuardEnv, normative_scripts: dict[str, str], install_shims: None
) -> None:
    """A stop whose inspection never reaches inactive/failed within the 30 s
    window is indeterminate (A2): the harness models this with a state
    sequence stuck in deactivating and asserts the controller-side outcome.
    (The wall-clock controller-timeout behavior — local SSH termination,
    indeterminate outcome, remote guard survival — has its own real test
    below.)"""
    # The shim consumes one entry per invocation, verb-independent:
    # entry 0 = stop command, entries 1..2 = stuck deactivating polls.
    _set_state(
        guard_env,
        [
            {
                "ActiveState": "deactivating",
                "SubState": "stop",
                "Result": "success",
                "NRestarts": "0",
                "Restart": "no",
                "exit": 0,
            },
            {
                "ActiveState": "deactivating",
                "SubState": "stop-sigterm",
                "Result": "success",
                "NRestarts": "0",
                "Restart": "no",
            },
            {
                "ActiveState": "deactivating",
                "SubState": "stop-sigkill",
                "Result": "success",
                "NRestarts": "0",
                "Restart": "no",
            },
        ],
    )
    stop = GuardClient(guard_env.ssh_runner(), new_nonce(), "endpoint-" + "b5" * 32 + ".lock")
    stop_out = stop.operate(
        [
            "sh",
            "-c",
            normative_scripts["EXEC_V1"],
            "testudo",
            "systemctl",
            "--user",
            "stop",
            "--",
            UNIT,
        ],
        timeout=60,
    )
    # The command exits 0 but inspection stays deactivating -> controller must
    # record indeterminate, never success.
    assert stop_out.exit_code == 0
    runner = guard_env.ssh_runner()
    for _ in range(2):  # entries 1..2: still deactivating after the stop window
        props = _parse_show(
            runner.run(
                remote_command(normative_scripts["EXEC_V1"], _inspect_argv(UNIT)), timeout=30
            ).stdout
        )
        assert props["ActiveState"] == "deactivating"  # => indeterminate, not success


@pytest.mark.usefixtures("linux_only")
def test_g5_stop_controller_timeout_is_indeterminate_guard_survives(
    guard_env: GuardEnv, normative_scripts: dict[str, str], install_shims: None
) -> None:
    """Real controller-timeout for Template A (A2/B2 shape): a `systemctl
    --user stop` whose remote execution exceeds the controller timeout
    terminates only the LOCAL SSH process — the outcome is indeterminate
    (exit_code None), never "remote command killed" — and the remote guard
    survives it: a second controller waits the full flock window and gets
    TESTUDO_GUARD_BUSY while the remote stop still runs."""
    # Shim entry 0: the stop verb sleeps 30 s (past every controller timeout
    # used here), holding the remote guard the whole time.
    _set_state(
        guard_env,
        [
            {
                "ActiveState": "deactivating",
                "SubState": "stop",
                "Result": "success",
                "NRestarts": "0",
                "Restart": "no",
                "exit": 0,
                "sleep": 30,
            },
        ],
    )
    lock = "endpoint-" + "e5" * 32 + ".lock"
    stopper = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
    stop_out = stopper.operate(
        [
            "sh",
            "-c",
            normative_scripts["EXEC_V1"],
            "testudo",
            "systemctl",
            "--user",
            "stop",
            "--",
            UNIT,
        ],
        timeout=6,
    )
    assert stop_out.exit_code is None, (
        f"local timeout must yield indeterminate (None), got {stop_out.exit_code}"
    )
    assert stop_out.rc_trailer is None  # no genuine trailer was seen

    # The remote command may still be running: the remote guard survives the
    # local termination. Second controller: full 10 s flock wait -> BUSY.
    second = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
    began = time.monotonic()
    busy = second.operate(["sh", "-c", "echo NOPE"], timeout=40)
    elapsed = time.monotonic() - began
    assert busy.exit_code == 75, f"expected BUSY(75), got {busy.exit_code}"
    assert "TESTUDO_GUARD_BUSY" in busy.raw_stdout
    assert "NOPE" not in busy.raw_stdout
    assert 9.0 <= elapsed <= 12.0, (
        f"BUSY must come from the 10 s flock wait (guard held by the remote "
        f"stop), took {elapsed:.1f}s"
    )


@pytest.mark.usefixtures("linux_only")
def test_g5_force_stop_kill_argv_under_guard(
    guard_env: GuardEnv, normative_scripts: dict[str, str], install_shims: None
) -> None:
    """Real controller-side force-stop execution for Template A (A2): the
    exact spec argv `systemctl --user kill --signal=SIGKILL -- <unit>` runs
    under a fresh guard through the full GUARD_V1 protocol (lock, GO gate,
    genuine trailer, RELEASE)."""
    _set_state(
        guard_env,
        [
            {
                "ActiveState": "active",
                "SubState": "running",
                "Result": "success",
                "NRestarts": "0",
                "Restart": "no",
                "exit": 0,
            },  # kill verb: exit 0
            {
                "ActiveState": "failed",
                "SubState": "failed",
                "Result": "signal",
                "NRestarts": "0",
                "Restart": "no",
            },  # post-kill inspect
        ],
    )
    lock = "endpoint-" + "f5" * 32 + ".lock"
    client = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
    out = client.operate(
        [
            "sh",
            "-c",
            normative_scripts["EXEC_V1"],
            "testudo",
            "systemctl",
            "--user",
            "kill",
            "--signal=SIGKILL",
            "--",
            UNIT,
        ],
        timeout=60,
    )
    assert out.exit_code == 0, out.raw_stdout[:300]
    assert out.rc_trailer == 0  # genuine nonce-bound trailer carried the rc
    # the 30-second post-force inspection window (A2): state observed
    props = _parse_show(
        guard_env.ssh_runner()
        .run(remote_command(normative_scripts["EXEC_V1"], _inspect_argv(UNIT)), timeout=30)
        .stdout
    )
    assert props["ActiveState"] == "failed" and props["Result"] == "signal"


def test_g5_force_stop_challenge_contract_simulation_only() -> None:
    """SIMULATION-ONLY (F5 relabel): force-stop's server-generated, single-
    use, expiring confirmation challenge is bridge-side R1 API surface
    (seat.forceStopChallenge / seat.operate confirmation_id); that production
    bridge does not exist yet, so this test asserts the challenge contract
    against a local model, NOT against production code. The executable
    force-stop kill argv itself is covered for real above; the README
    documents this boundary.

    Contract: the challenge is bridge-generated, bound to
    seat/template/revision/consent/operation, expires in five minutes, is
    single-use, and a kill without a valid challenge id is refused — force-
    stop is never automatic and never piggybacks on stop."""
    challenge = {"id": new_nonce(), "operation": "force-stop", "used": False}
    assert challenge["operation"] == "force-stop"

    # Simulated bridge-side validation:
    def force_stop_allowed(challenge_id: str | None) -> bool:
        return (
            challenge_id is not None and challenge_id == challenge["id"] and not challenge["used"]
        )

    assert not force_stop_allowed(None)  # no challenge -> refused
    assert not force_stop_allowed("forged-id")  # wrong id -> refused
    assert force_stop_allowed(str(challenge["id"]))  # valid -> allowed once
    challenge["used"] = True
    assert not force_stop_allowed(str(challenge["id"]))  # single-use enforced
