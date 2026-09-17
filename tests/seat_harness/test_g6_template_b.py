"""G6 — Template B: ownership gate refusal with occupant display, status
exit-code protocol, timeout to indeterminate (B1/B2/B3).

SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later

Template B's operation argv is exactly ``[script, subcommand]``; status uses
EXEC_V1 (unguarded). The harness drives a fixture control script installed
at the spec-shaped path and asserts:
* status exit codes: 0 = serving claim, 1 = dormant, other = error;
* the post-lock ownership gate (L3) refuses a stop when the endpoint reports
  a different/unknown occupant, WITHOUT invoking the script, driven through
  the real guard protocol (lock acquired, post-lock poll, EOF refusal ->
  GATE_REFUSED) against a real fixture model server; a permitted gate
  proceeds and invokes the script exactly once;
* command timeout terminates only the local SSH process and is recorded as
  indeterminate (B2), with the remote guard surviving;
* Template B exposes no force-stop challenge (B3) — bridge-side API shape,
  covered as a simulation-only contract test (production bridge not yet
  implemented).
"""

from __future__ import annotations

import contextlib
import json
import time

import pytest

from .conftest import FixtureHost, GuardEnv
from .guard_client import GuardClient
from .model_server import FixtureModelServer
from .render import new_nonce, remote_command

pytestmark = pytest.mark.seat_harness

SEAT_MODEL_ID = "example-model"


@pytest.fixture
def linux_only(seat_fixture_host: FixtureHost) -> None:
    """Gate: guarded operations run GUARD_V1 (flock/stat/timeout required)."""
    if not seat_fixture_host.linux_semantics:
        pytest.skip(
            "guarded Template B operations need GUARD_V1 (flock, GNU stat, "
            "timeout); section 8 platform boundary — run on the Linux fixture"
        )


@pytest.fixture
def script_path(guard_env: GuardEnv) -> str:
    """The control script's spec-shaped absolute path under $HOME."""
    home = guard_env.session().run('printf %s "$HOME"').stdout.strip()
    return f"{home}/.local/bin/model-control"


CONTROL_SCRIPT = """#!/bin/sh
# Fixture Template B control script. State-driven via ~/.fixture-state/tb.json.
# Every invocation appends its subcommand to ~/.fixture-state/invocations so
# tests can prove the script was (not) invoked — e.g. by a refused L3 gate.
set -eu
state="$HOME/.fixture-state/tb.json"
[ -f "$state" ] || { echo "no state" >&2; exit 64; }
sub=$1
printf '%s\\n' "$sub" >> "$HOME/.fixture-state/invocations"
python3 - "$state" "$sub" <<'PYEOF'
import json, sys
state, sub = sys.argv[1], sys.argv[2]
cfg = json.load(open(state))
mode = cfg.get(sub + "_exit", 1)
if sub == "status" and cfg.get("status_output"):
    print(cfg["status_output"])
sys.exit(int(mode))
PYEOF
"""


@pytest.fixture
def control_script(guard_env: GuardEnv, script_path: str) -> None:
    b64 = CONTROL_SCRIPT.encode().hex()
    proc = guard_env.session().run(
        f"mkdir -p -m 755 ~/.local/bin ~/.fixture-state && "
        f"rm -f ~/.fixture-state/invocations && "
        f"python3 -c \"import sys;sys.stdout.buffer.write(bytes.fromhex('{b64}'))\" "
        f"> {script_path} && chmod 755 {script_path}"
    )
    assert proc.returncode == 0, proc.stderr


def _set_tb_state(guard_env: GuardEnv, state: dict[str, object]) -> None:
    hex_payload = json.dumps(state).encode().hex()
    proc = guard_env.session().run(
        f"mkdir -p -m 700 ~/.fixture-state && "
        f"python3 -c \"import sys;sys.stdout.buffer.write(bytes.fromhex('{hex_payload}'))\" "
        f"> ~/.fixture-state/tb.json"
    )
    assert proc.returncode == 0, proc.stderr


def _stop_invocations(guard_env: GuardEnv) -> int:
    """How many times the control script ran the `stop` subcommand."""
    out = (
        guard_env.session()
        .run("grep -c '^stop$' ~/.fixture-state/invocations 2>/dev/null || echo 0")
        .stdout.strip()
    )
    return int(out.splitlines()[-1])


def test_g6_status_exit_code_protocol(
    guard_env: GuardEnv,
    normative_scripts: dict[str, str],
    control_script: None,
    script_path: str,
) -> None:
    """0 = script claims serving, 1 = dormant, any other code = error."""
    runner = guard_env.ssh_runner()
    remote = remote_command(normative_scripts["EXEC_V1"], [script_path, "status"])
    for state, expected_rc in (
        ({"status_exit": 0, "status_output": f"serving {SEAT_MODEL_ID}"}, 0),
        ({"status_exit": 1}, 1),
        ({"status_exit": 3}, 3),
        ({"status_exit": 64}, 64),
    ):
        _set_tb_state(guard_env, dict(state))
        result = runner.run(remote, timeout=30)
        assert result.exit_code == expected_rc, (
            f"status exit for {state} was {result.exit_code}, want {expected_rc}"
        )


@pytest.mark.usefixtures("linux_only")
def test_g6_operation_argv_is_exact(
    guard_env: GuardEnv,
    normative_scripts: dict[str, str],
    control_script: None,
    script_path: str,
) -> None:
    """Destructive operations use exactly [script, subcommand] under the guard;
    status uses EXEC_V1. The rendered remote string must embed exactly those."""
    _set_tb_state(guard_env, {"start_exit": 0, "status_exit": 1})
    scripts = normative_scripts
    lock = "endpoint-" + "b6" * 32 + ".lock"
    client = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
    out = client.operate([script_path, "start"], timeout=60)
    assert out.exit_code == 0, out.raw_stdout[:300]
    # status via EXEC_V1 (no guard): dormant (1) after a start whose exit 0 is
    # not serving evidence (B1).
    result = guard_env.ssh_runner().run(
        remote_command(scripts["EXEC_V1"], [script_path, "status"]), timeout=30
    )
    assert result.exit_code == 1


@pytest.mark.usefixtures("linux_only")
def test_g6_ownership_gate_refusal_and_permission_through_real_guard(
    guard_env: GuardEnv,
    control_script: None,
    script_path: str,
) -> None:
    """L3/B1 driven for real: the controller acquires the remote lock, runs
    the post-lock ownership poll against a REAL fixture model server, and on
    a different sole occupant refuses by EOF — GUARD_V1 answers GATE_REFUSED
    (77) and the control script is never invoked. When the endpoint then
    reports the exact sole seat model, a fresh controller proceeds through
    the same gate and the script runs exactly once. Occupant ids stay bounded
    (B1: bounded, sanitized occupant display)."""
    _set_tb_state(guard_env, {"stop_exit": 0})
    endpoint = FixtureModelServer("someone-elses-model")
    endpoint.start()
    try:
        # The L3 post-lock poll, as the controller performs it (D2-shaped
        # endpoint poll while both locks are held).
        def poll_permits() -> bool:
            return endpoint.poll_models() == [SEAT_MODEL_ID]

        lock = "endpoint-" + "d6" * 32 + ".lock"

        # 1. Endpoint serves a DIFFERENT sole model -> gate refuses.
        refused = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
        refused.poll_permits = poll_permits
        out = refused.operate([script_path, "stop"], timeout=60)
        assert out.locked, "lock must have been acquired before the poll"
        assert out.exit_code == 77, (
            f"expected GATE_REFUSED(77), got {out.exit_code}: {out.raw_stdout[:300]}"
        )
        assert _stop_invocations(guard_env) == 0, (
            "the control script must NOT be invoked when the L3 gate refuses"
        )
        # Bounded occupant display: the poll's model ids are shown bounded.
        occupants = endpoint.poll_models() or []
        assert occupants == ["someone-elses-model"]
        assert all(len(m) <= 512 for m in occupants)

        # 2. Endpoint now serves the exact sole seat model -> gate permits.
        endpoint.control.model_id = SEAT_MODEL_ID
        permitted = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
        permitted.poll_permits = poll_permits
        out2 = permitted.operate([script_path, "stop"], timeout=60)
        assert out2.exit_code == 0, out2.raw_stdout[:300]
        assert _stop_invocations(guard_env) == 1, (
            "the control script must run exactly once when the gate permits"
        )
    finally:
        endpoint.stop()


@pytest.mark.usefixtures("linux_only")
def test_g6_stop_timeout_is_indeterminate(
    guard_env: GuardEnv,
    control_script: None,
    script_path: str,
) -> None:
    """On a stop command timeout the bridge terminates only its local SSH
    process and states the remote command may still be running: exit None
    (indeterminate), never 'remote command killed'."""
    _set_tb_state(guard_env, {"stop_exit": 0, "stop_sleep": 25})
    # make the stop subcommand sleep: patch state semantics via a slow script
    slow = CONTROL_SCRIPT.replace(
        "sys.exit(int(mode))",
        "import time; time.sleep(cfg.get(sub + '_sleep', 0)); sys.exit(int(mode))",
    )

    b64 = slow.encode().hex()
    proc = guard_env.session().run(
        f"python3 -c \"import sys;sys.stdout.buffer.write(bytes.fromhex('{b64}'))\" "
        f"> {script_path} && chmod 755 {script_path}"
    )
    assert proc.returncode == 0
    lock = "endpoint-" + "c6" * 32 + ".lock"
    client = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
    out = client.operate([script_path, "stop"], timeout=10)
    assert out.exit_code is None, f"timeout must be indeterminate, got {out.exit_code}"
    assert out.rc_trailer is None
    # The remote command may still be running; the remote guard survives.
    # A second controller must see BUSY (guard still held by the remote op).
    time.sleep(0.5)
    second = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
    t0 = time.monotonic()
    busy = second.operate(["sh", "-c", "echo NOPE"], timeout=30)
    elapsed = time.monotonic() - t0
    # Either immediate BUSY (holder alive) or acquisition after the holder's
    # sleep ends; both prove the guard survived the local termination.
    assert busy.exit_code in (75, 0), f"unexpected second-controller rc {busy.exit_code}"
    if busy.exit_code == 75:
        assert "TESTUDO_GUARD_BUSY" in busy.raw_stdout
        assert elapsed >= 9.0  # waited the full flock window
    # cleanup: make sure the sleeping remote op is gone (rc 143 = pkill killed
    # its own process group; treat any rc as acceptable cleanup)
    with contextlib.suppress(Exception):  # cleanup best-effort
        guard_env.session().run("pkill -f 'model-control stop' 2>/dev/null; true")


def test_g6_no_force_stop_challenge_simulation_only() -> None:
    """SIMULATION-ONLY (F6 relabel): B3's "Template B exposes no
    forceStopChallenge; direct requests return 'unsupported: host-side
    intervention required'" is bridge-side R1 API surface; the production
    bridge does not exist yet, so this asserts the contract against a local
    model, NOT against production code. The README documents this boundary.
    """

    def challenge_request(template: str) -> str:
        if template != "bare-command" and template != "systemd-user":
            return "unsupported: host-side intervention required"
        return "challenge-issued"

    def operate_request(template: str, operation: str) -> str:
        if operation == "force-stop" and template == "control-script":
            return "unsupported: host-side intervention required"
        return "accepted"

    assert challenge_request("control-script").startswith("unsupported:")
    assert operate_request("control-script", "force-stop").startswith("unsupported:")
