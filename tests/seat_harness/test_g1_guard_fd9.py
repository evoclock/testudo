"""G1 — GUARD_V1 regression: descendants do not hold FD 9 (L2).

SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later

The Revision 4 review found the FD-inheritance deadlock by reading; section 8
demands an execution-shaped regression test. This module:

1. runs a real Template C start (LAUNCH_V1 under GUARD_V1),
2. asserts the started server does NOT have FD 9 open (/proc/<pid>/fd),
3. immediately runs a stop (C_PID_V1) under a fresh guard on the SAME lock —
   if the start had leaked FD 9, the stop's ``flock --wait 10`` would block
   for 10 s and fail with TESTUDO_GUARD_BUSY; it must instead succeed fast,
4. proves the negative control: a descendant that deliberately takes the
   flock on FD 9 makes the next controller BUSY (so the detector is real).
"""

from __future__ import annotations

import threading
import time

import pytest

from .conftest import FixtureHost, GuardEnv
from .guard_client import GuardClient
from .render import argv_sha256, new_nonce

pytestmark = pytest.mark.seat_harness

SERVER_PORT = 8101


def _upload_server(guard_env: GuardEnv, name: str) -> None:
    import base64
    from pathlib import Path

    srv = Path(__file__).resolve().parent / "data" / name
    b64 = base64.b64encode(srv.read_bytes()).decode()
    guard_env.session().run(f"mkdir -p -m 755 ~/bin && echo {b64!r} | base64 -d > ~/bin/{name}")


def _launch_argv(port: int) -> list[str]:
    return [
        "/usr/local/bin/python3",
        "/home/fixture/bin/fixture_srv_slow_exit.py",
        str(port),
    ]


@pytest.fixture
def linux_only(seat_fixture_host: FixtureHost) -> None:
    """Gate: Template C semantics (/proc, setsid, flock) need the Linux fixture."""
    if not seat_fixture_host.linux_semantics:
        pytest.skip(
            "Template C PID-identity semantics require Linux /proc + util-linux; "
            "section 8 documents this platform boundary (run on Linux CI or with "
            "Docker available)"
        )


@pytest.mark.usefixtures("linux_only")
def test_g1_started_descendants_do_not_hold_fd9(
    guard_env: GuardEnv, normative_scripts: dict[str, str]
) -> None:
    """After a successful Template C start, a subsequent stop acquires the
    guard and succeeds — the Revision 4 FD-inheritance deadlock regression."""
    _upload_server(guard_env, "fixture_srv_slow_exit.py")
    scripts = normative_scripts
    launch_argv = _launch_argv(SERVER_PORT)
    expected = argv_sha256(launch_argv)
    lock = "endpoint-" + "11" * 32 + ".lock"

    start_client = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
    start_out = start_client.operate(
        ["sh", "-c", scripts["LAUNCH_V1"], "testudo", "", "g1-seat", expected, *launch_argv],
        timeout=90,
    )
    assert start_out.exit_code == 0, f"start failed: {start_out.raw_stdout[:400]}"
    pid_line = next(line for line in start_out.stdout_lines if line.startswith("TESTUDO_PID "))
    _, pid, pgid, start_ticks, boot_id, argv_hash = pid_line.split(" ")

    # The started process must not hold FD 9.
    fds = guard_env.session().run(f"ls /proc/{pid}/fd/ 2>/dev/null").stdout.split()
    assert "9" not in fds, f"started process {pid} inherited FD 9: {fds}"

    # A subsequent stop must acquire the guard and succeed quickly (not BUSY).
    # Spec §3.4.3: stop runs C_PID_V1 exactly as the C2 construction renders
    # it — `sh -c <C_PID_V1> testudo stop ...` (dash on Debian, no bash).
    stop_client = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
    began = time.monotonic()
    stop_out = stop_client.operate(
        [
            "sh",
            "-c",
            scripts["C_PID_V1"],
            "testudo",
            "stop",
            pid,
            pgid,
            start_ticks,
            boot_id,
            argv_hash,
        ],
        timeout=90,
    )
    elapsed = time.monotonic() - began
    assert stop_out.exit_code == 0, (
        f"stop failed rc={stop_out.exit_code}: {stop_out.raw_stdout[:400]}"
    )
    assert elapsed < 10, f"stop took {elapsed:.1f}s — guard was held (FD 9 leak?)"


@pytest.mark.usefixtures("linux_only")
def test_g1_negative_control_fd9_holder_makes_next_controller_busy(
    guard_env: GuardEnv,
) -> None:
    """A descendant that holds the flock on FD 9 makes the next controller
    BUSY after the 10-second wait — proving the detector above is real."""
    lock = "endpoint-" + "88" * 32 + ".lock"
    holder_client = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
    result: dict[str, object] = {}

    def run_holder() -> None:
        # Deliberate leak shape: descendant opens the lock on FD 9 and flocks it.
        result["out"] = holder_client.operate(
            [
                "sh",
                "-c",
                'nohup sh -c "exec 9<>\\"$HOME/.testudo/'
                + lock
                + '\\"; flock -e 9; sleep 12" >/dev/null 2>&1 & sleep 0.3; exit 0',
            ],
            timeout=60,
        )

    thread = threading.Thread(target=run_holder, daemon=True)
    thread.start()
    time.sleep(2.0)

    next_client = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
    began = time.monotonic()
    busy_out = next_client.operate(["sh", "-c", "echo SHOULD_NOT_RUN"], timeout=30)
    elapsed = time.monotonic() - began
    assert busy_out.exit_code == 75, f"expected BUSY(75), got {busy_out.exit_code}"
    assert "TESTUDO_GUARD_BUSY" in busy_out.raw_stdout
    assert 9.0 <= elapsed <= 12.0, f"BUSY must come from the 10s flock wait, took {elapsed:.1f}s"
    thread.join(timeout=30)
