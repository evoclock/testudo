"""G2 — LAUNCH_V1 / C_PID_V1 PID identity (C3).

SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later

Verifies by execution: PID capture from the exact TESTUDO_PID line,
argv_sha256 byte-exactness (each UTF-8 element followed by one NUL, final
argument NUL-terminated, matching /proc/<pid>/cmdline raw bytes), start-time
identity, PGID == pid (setsid invariant), and the TERM-then-KILL escalation
of C_PID_V1 stop against a TERM-ignoring fixture server.
"""

from __future__ import annotations

import hashlib
import time

import pytest

from .conftest import FixtureHost, GuardEnv
from .guard_client import GuardClient
from .render import argv_sha256, new_nonce

pytestmark = pytest.mark.seat_harness

FAST_PORT = 8111
STUBBORN_PORT = 8112
FAST_EXIT_PORTS = (8113, 8114, 8115)


def _upload(guard_env: GuardEnv, name: str) -> None:
    import base64
    from pathlib import Path

    srv = Path(__file__).resolve().parent / "data" / name
    b64 = base64.b64encode(srv.read_bytes()).decode()
    guard_env.ssh_runner().run(f"mkdir -p -m 755 ~/bin && echo {b64!r} | base64 -d > ~/bin/{name}")


@pytest.fixture
def linux_only(seat_fixture_host: FixtureHost) -> None:
    if not seat_fixture_host.linux_semantics:
        pytest.skip(
            "PID-identity tests need Linux /proc + util-linux setsid (section 8 "
            "platform boundary); exercised on Linux CI / Docker-available hosts"
        )


@pytest.mark.usefixtures("linux_only")
def test_g2_pid_capture_and_identity(
    guard_env: GuardEnv, normative_scripts: dict[str, str]
) -> None:
    _upload(guard_env, "fixture_srv.py")
    scripts = normative_scripts
    launch_argv = [
        "/usr/local/bin/python3",
        "/home/fixture/bin/fixture_srv.py",
        str(FAST_PORT),
        "--flag",  # option token element: hashed like any other
        "value1",
    ]
    expected = argv_sha256(launch_argv)
    # Independent recomputation of the byte layout: element + NUL, final NUL.
    manual = hashlib.sha256(b"".join(e.encode("utf-8") + b"\x00" for e in launch_argv)).hexdigest()
    assert expected == manual

    client = GuardClient(guard_env.ssh_runner(), new_nonce(), "endpoint-" + "21" * 32 + ".lock")
    out = client.operate(
        ["sh", "-c", scripts["LAUNCH_V1"], "testudo", "", "g2-seat", expected, *launch_argv],
        timeout=90,
    )
    assert out.exit_code == 0, out.raw_stdout[:400]
    pid_line = next(line for line in out.stdout_lines if line.startswith("TESTUDO_PID "))
    _, pid, pgid, start_ticks, boot_id, argv_hash = pid_line.split(" ")

    # argv_sha256 matches raw /proc bytes (including the final NUL).
    remote_hash = (
        guard_env.session().run(f"sha256sum /proc/{pid}/cmdline | cut -d' ' -f1").stdout.strip()
    )
    assert argv_hash == expected == remote_hash
    # cmdline bytes: exactly the elements, NUL-separated, NUL-terminated, no extra.
    raw = guard_env.session().run(f"cat /proc/{pid}/cmdline | od -c | tail -3").stdout
    assert r"\0" in raw  # NUL-terminated final argument visible in od output

    # PGID == pid (setsid foreground invariant), start ticks sane, boot id a UUID.
    assert pgid == pid
    statline = guard_env.session().run(f"cat /proc/{pid}/stat").stdout.strip()
    assert statline.split(") ", 1)[1].split()[19] == start_ticks  # field 20 (1-based)
    assert len(boot_id) == 36 and boot_id.count("-") == 4

    # inspect mode accepts the exact identity (spec §3.4.3: C_PID_V1 under
    # the remote sh — dash on the Debian fixture — never bash).
    insp = GuardClient(guard_env.ssh_runner(), new_nonce(), "endpoint-" + "21" * 32 + ".lock")
    insp_out = insp.operate(
        [
            "sh",
            "-c",
            scripts["C_PID_V1"],
            "testudo",
            "inspect",
            pid,
            pgid,
            start_ticks,
            boot_id,
            argv_hash,
        ],
        timeout=60,
    )
    assert insp_out.exit_code == 0 and "TESTUDO_PID_MATCH" in insp_out.raw_stdout


@pytest.mark.usefixtures("linux_only")
def test_g2_term_then_kill_escalation(
    guard_env: GuardEnv, normative_scripts: dict[str, str]
) -> None:
    """A TERM-ignoring server forces the C_PID_V1 escalation: after ~10 s of
    TERM waiting (100 x 0.1 s), KILL terminates the process group."""
    _upload(guard_env, "fixture_srv_stubborn.py")
    scripts = normative_scripts
    launch_argv = [
        "/usr/local/bin/python3",
        "/home/fixture/bin/fixture_srv_stubborn.py",
        str(STUBBORN_PORT),
    ]
    client = GuardClient(guard_env.ssh_runner(), new_nonce(), "endpoint-" + "22" * 32 + ".lock")
    out = client.operate(
        [
            "sh",
            "-c",
            scripts["LAUNCH_V1"],
            "testudo",
            "",
            "g2-stubborn",
            argv_sha256(launch_argv),
            *launch_argv,
        ],
        timeout=90,
    )
    assert out.exit_code == 0, out.raw_stdout[:400]
    _, pid, pgid, start_ticks, boot_id, argv_hash = next(
        line for line in out.stdout_lines if line.startswith("TESTUDO_PID ")
    ).split(" ")

    began = time.monotonic()
    stop = GuardClient(guard_env.ssh_runner(), new_nonce(), "endpoint-" + "22" * 32 + ".lock")
    stop_out = stop.operate(
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
        timeout=120,
    )
    elapsed = time.monotonic() - began
    # The amended script exits 0 on every stop path (identity match through
    # the loop, post-TERM disappearance, or KILL escalation); 79 is refusal
    # only. The stubborn server forces the ~10 s TERM window before KILL.
    assert elapsed > 9.0, f"escalation window too short: {elapsed:.1f}s"
    assert stop_out.exit_code == 0, (
        f"unexpected stop exit {stop_out.exit_code}: {stop_out.raw_stdout[:300]}"
    )
    alive = (
        guard_env.session()
        .run(f"kill -0 {pid} 2>/dev/null && echo ALIVE || echo DEAD")
        .stdout.strip()
    )
    assert alive == "DEAD", "KILL escalation failed to terminate the process group"


@pytest.mark.usefixtures("linux_only")
def test_g2_fast_exit_stop_is_success_not_race_79(
    guard_env: GuardEnv, normative_scripts: dict[str, str]
) -> None:
    """Revision 5 amendment regression: a process that dies immediately on
    TERM must make C_PID_V1 exit 0 (the kill worked — disappearance after
    TERM is success), never 79. The pre-amendment script raced `kill -0`
    against `verify` and could exit 79 for a successfully-killed fast-exiting
    process. Three launch/stop rounds hammer the vanish window; the fixture
    server (default TERM disposition) is deterministic, so every round must
    exit exactly 0 and leave the process gone."""
    _upload(guard_env, "fixture_srv.py")
    scripts = normative_scripts
    for i, port in enumerate(FAST_EXIT_PORTS):
        launch_argv = [
            "/usr/local/bin/python3",
            "/home/fixture/bin/fixture_srv.py",
            str(port),
        ]
        lock = "endpoint-" + f"{24 + i:02d}" * 32 + ".lock"
        launch = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
        out = launch.operate(
            [
                "sh",
                "-c",
                scripts["LAUNCH_V1"],
                "testudo",
                "",
                f"g2-fast-{i}",
                argv_sha256(launch_argv),
                *launch_argv,
            ],
            timeout=90,
        )
        assert out.exit_code == 0, out.raw_stdout[:400]
        _, pid, pgid, start_ticks, boot_id, argv_hash = next(
            line for line in out.stdout_lines if line.startswith("TESTUDO_PID ")
        ).split(" ")

        stop = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
        stop_out = stop.operate(
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
            timeout=60,
        )
        assert stop_out.exit_code == 0, (
            f"round {i}: fast-exit stop must be success (0), got "
            f"{stop_out.exit_code}: {stop_out.raw_stdout[:300]}"
        )
        alive = (
            guard_env.session()
            .run(f"kill -0 {pid} 2>/dev/null && echo ALIVE || echo DEAD")
            .stdout.strip()
        )
        assert alive == "DEAD", f"round {i}: process {pid} still alive after stop"


@pytest.mark.usefixtures("linux_only")
def test_g2_identity_mismatch_refuses_signal(
    guard_env: GuardEnv, normative_scripts: dict[str, str]
) -> None:
    """Wrong start-ticks (PID-reuse shape) must refuse signaling with exit 79
    and must not deliver any signal."""
    scripts = normative_scripts
    fake = ["999999", "999999", "1", "00000000-0000-0000-0000-000000000000", "0" * 64]
    stop = GuardClient(guard_env.ssh_runner(), new_nonce(), "endpoint-" + "23" * 32 + ".lock")
    out = stop.operate(
        ["sh", "-c", scripts["C_PID_V1"], "testudo", "stop", *fake],
        timeout=60,
    )
    assert out.exit_code == 79, f"expected identity refusal (79), got {out.exit_code}"
