"""G7 — Lingering shim: Linger=yes gate, warning path, post-session poll
requirement (U1, R-2).

SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later

Executes the spec's exact U1 lifetime probe
``remote_command(EXEC_V1, ["loginctl","show-user",<user>,"--property=Linger","--value"])``
against the fixture loginctl shim and asserts:
* Linger=yes gates a start (enabled);
* Linger=no and unknown (missing logind/user manager) display the exact
  warning "service may stop when this session ends" and refuse start as
  "host lifetime prerequisite", while inspect and ownership-safe stop remain
  available;
* Testudo never runs ``loginctl enable-linger`` (the shim rejects it);
* the post-session endpoint poll requirement: a start cannot be reported
  serving until the guarded SSH command has closed normally AND a fresh
  post-session poll still reports the exact sole model (a server killed at
  session teardown must not yield a false serving).
"""

from __future__ import annotations

import pytest

from .conftest import GuardEnv
from .model_server import FixtureModelServer
from .render import remote_command
from .shims import write_linger_state

pytestmark = pytest.mark.seat_harness

WARNING_TEXT = "service may stop when this session ends"
REFUSAL_REASON = "host lifetime prerequisite"


def _set_linger(guard_env: GuardEnv, value: str | None) -> None:
    hex_payload = write_linger_state(value).encode().hex()
    proc = guard_env.session().run(
        f"mkdir -p -m 700 ~/.fixture-state && "
        f"python3 -c \"import sys;sys.stdout.buffer.write(bytes.fromhex('{hex_payload}'))\" "
        f"> ~/.fixture-state/linger.json"
    )
    assert proc.returncode == 0, proc.stderr


def _linger_probe(
    guard_env: GuardEnv, normative_scripts: dict[str, str], user: str = "fixture"
) -> tuple[int, str]:
    runner = guard_env.ssh_runner()
    remote = remote_command(
        normative_scripts["EXEC_V1"],
        ["loginctl", "show-user", user, "--property=Linger", "--value"],
    )
    result = runner.run(remote, timeout=30)
    rc = result.exit_code if result.exit_code is not None else -1
    return rc, result.stdout.strip()


@pytest.mark.parametrize("value,expected", [("yes", "yes"), ("no", "no")])
def test_g7_linger_yes_no(
    guard_env: GuardEnv,
    normative_scripts: dict[str, str],
    install_shims: None,
    value: str,
    expected: str,
) -> None:
    _set_linger(guard_env, value)
    rc, out = _linger_probe(guard_env, normative_scripts)
    assert rc == 0 and out == expected


def test_g7_linger_unknown_missing_user_manager(
    guard_env: GuardEnv,
    normative_scripts: dict[str, str],
    install_shims: None,
) -> None:
    _set_linger(guard_env, None)
    rc, out = _linger_probe(guard_env, normative_scripts)
    assert rc != 0 or out == "", "missing logind/user manager must be unknown"

    # Controller mapping: any non-"yes"/"no" trimmed output or failure = unknown.
    def map_linger(rc: int, out: str) -> str:
        return out if rc == 0 and out in ("yes", "no") else "unknown"

    assert map_linger(rc, out) == "unknown"


def test_g7_start_gate_and_warning_paths_simulation_only() -> None:
    """SIMULATION-ONLY (F7 relabel): the U1 start gate (fresh `yes` enables
    start; `no`/`unknown` display the exact warning "service may stop when
    this session ends" and refuse start as "host lifetime prerequisite"
    while inspect and ownership-safe stop remain available) is bridge-side
    decision logic on top of the real linger probe; the production bridge
    does not exist yet, so this test asserts the gate contract against a
    local model, NOT against production code. The linger probe feeding the
    gate is executed for real against the fixture shim in the tests above,
    and the README documents this boundary.
    """

    class LifetimeGate:
        def __init__(self, linger: str) -> None:
            self.linger = linger

        def start_enabled(self) -> tuple[bool, str | None]:
            if self.linger == "yes":
                return True, None
            return False, REFUSAL_REASON

        def warning(self) -> str | None:
            return None if self.linger == "yes" else WARNING_TEXT

        def inspect_available(self) -> bool:
            return True

        def ownership_safe_stop_available(self) -> bool:
            return True

    for linger, start_ok in (("yes", True), ("no", False), ("unknown", False)):
        gate = LifetimeGate(linger)
        enabled, reason = gate.start_enabled()
        assert enabled is start_ok
        if not start_ok:
            assert reason == REFUSAL_REASON
            assert gate.warning() == WARNING_TEXT
        else:
            assert gate.warning() is None
        assert gate.inspect_available() and gate.ownership_safe_stop_available()


def test_g7_never_enables_linger(
    guard_env: GuardEnv,
    normative_scripts: dict[str, str],
    install_shims: None,
) -> None:
    """Testudo never runs loginctl enable-linger: the shim must reject it and
    the harness asserts no such call is part of any operation argv."""
    runner = guard_env.ssh_runner()
    result = runner.run(
        remote_command(normative_scripts["EXEC_V1"], ["loginctl", "enable-linger", "fixture"]),
        timeout=30,
    )
    assert result.exit_code != 0, "enable-linger must not succeed"
    # And the exact probe argv never contains enable-linger:
    remote = remote_command(
        normative_scripts["EXEC_V1"],
        ["loginctl", "show-user", "fixture", "--property=Linger", "--value"],
    )
    assert "enable-linger" not in remote


def test_g7_post_session_poll_requirement_simulation_only(
    guard_env: GuardEnv,
    normative_scripts: dict[str, str],
) -> None:
    """Post-session poll requirement (U1), partly real, decision simulated:
    the fixture model server, its hard kill, and the D2-shaped polls are
    REAL; the final serving/not-serving decision is bridge-side controller
    logic with no production implementation yet, so that rule is asserted
    against a local model (simulation-only boundary documented in README).

    A start cannot be reported serving until the guarded SSH command has
    closed normally AND a fresh post-session endpoint poll still reports the
    exact sole model. A server torn down at session logout must not yield a
    false serving."""
    endpoint = FixtureModelServer("example-model")
    endpoint.start()
    try:
        # During the SSH session: poll reports the exact sole model.
        assert endpoint.poll_models() == ["example-model"]
        # Session ends and host policy kills the server (logout teardown):
        endpoint.hard_kill()
        # Post-session poll: connection refused -> NOT serving.
        assert endpoint.poll_models() is None

        # Controller rule: serving requires BOTH closed-session AND fresh poll;
        # with the poll failing, the start must not be reported serving.
        def serving(closed_normally: bool, fresh_poll: list[str] | None, model: str) -> bool:
            return closed_normally and fresh_poll == [model]

        assert not serving(True, None, "example-model")
        # And a fresh poll reporting a different model also blocks serving.
        assert not serving(True, ["other-model"], "example-model")
        assert serving(True, ["example-model"], "example-model")
    finally:
        endpoint.stop()
