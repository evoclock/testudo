"""LOG_TAIL_V1 execution tests — safe log directory/file checks and the
bounded tail (C3 / section 7 C3 row: "safe log directory/file checks and
bounded tail").

SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later

The complete constant LOG_TAIL_V1 is extracted byte-exactly from the spec
and executed over a real SSH channel to the fixture: owner/mode 700 on
``~/.testudo/logs``, owner/mode 600 on the log file, symlink rejection at
both, and the exact ``tail -c 4096`` bound. GNU ``stat -c``/``tail -c``
semantics make these Linux-fixture tests (section 8 platform boundary).
"""

from __future__ import annotations

import pytest

from .conftest import FixtureHost, GuardEnv
from .render import remote_command

pytestmark = pytest.mark.seat_harness

BOUND = 4096


@pytest.fixture
def linux_only(seat_fixture_host: FixtureHost) -> None:
    if not seat_fixture_host.linux_semantics:
        pytest.skip(
            "LOG_TAIL_V1 checks need GNU stat -c and GNU tail -c (section 8 "
            "platform boundary); exercised on the Linux Docker fixture"
        )


def _tail(guard_env: GuardEnv, scripts: dict[str, str], seat: str):
    return guard_env.ssh_runner().run(remote_command(scripts["LOG_TAIL_V1"], [seat]), timeout=30)


def _fixture_uid(guard_env: GuardEnv) -> str:
    return guard_env.session().run("id -u").stdout.strip()


def _reset_logs(guard_env: GuardEnv, seat: str = "g9-logtail") -> None:
    guard_env.session().run(f"rm -f ~/.testudo/logs/{seat}.log; mkdir -p -m 700 -- ~/.testudo/logs")


@pytest.mark.usefixtures("linux_only")
def test_g9_tail_bound_and_exact_suffix(
    guard_env: GuardEnv, normative_scripts: dict[str, str]
) -> None:
    """`exec tail -c 4096 -- "$log"` returns exactly the last 4096 bytes of a
    larger file, and the whole file when it is smaller than the bound."""
    seat = "g9-logtail"
    session = guard_env.session()
    _reset_logs(guard_env, seat)
    # 8 KiB file: first half filler, second half a recognizable exact suffix.
    session.run(
        f"printf '%s' \"$(python3 -c \"print('X'*{BOUND}, end='')\")\""
        f" > ~/.testudo/logs/{seat}.log && chmod 600 -- ~/.testudo/logs/{seat}.log"
    )
    session.run(f"python3 -c \"print('TAILMARK', end='')\" >> ~/.testudo/logs/{seat}.log")
    expected_tail = "X" * (BOUND - 8) + "TAILMARK"
    result = _tail(guard_env, normative_scripts, seat)
    assert result.exit_code == 0, f"LOG_TAIL_V1 failed: {result.stderr[:200]}"
    assert result.stdout == expected_tail, (
        f"tail bound wrong: got {len(result.stdout)} bytes, expected {len(expected_tail)}"
    )

    # Sub-bound file: the complete file comes back unchanged.
    session.run(f"rm -f ~/.testudo/logs/{seat}.log")
    session.run(
        f"printf 'short log line\\n' > ~/.testudo/logs/{seat}.log "
        f"&& chmod 600 -- ~/.testudo/logs/{seat}.log"
    )
    small = _tail(guard_env, normative_scripts, seat)
    assert small.exit_code == 0
    assert small.stdout == "short log line\n"


@pytest.mark.usefixtures("linux_only")
def test_g9_rejects_wrong_owner_or_mode(
    guard_env: GuardEnv, normative_scripts: dict[str, str]
) -> None:
    """Owner/mode enforcement: logs dir must be <uid>:700 and the log file
    <uid>:600; anything else exits 78 without emitting log content."""
    seat = "g9-modes"
    session = guard_env.session()
    _reset_logs(guard_env, seat)
    session.run(
        f"printf 'SECRETLOGDATA\\n' > ~/.testudo/logs/{seat}.log "
        f"&& chmod 600 -- ~/.testudo/logs/{seat}.log"
    )

    for mutate, restore in (
        ("chmod 755 -- ~/.testudo/logs", "chmod 700 -- ~/.testudo/logs"),
        (f"chmod 644 -- ~/.testudo/logs/{seat}.log", f"chmod 600 -- ~/.testudo/logs/{seat}.log"),
        (f"chmod 666 -- ~/.testudo/logs/{seat}.log", f"chmod 600 -- ~/.testudo/logs/{seat}.log"),
    ):
        session.run(mutate)
        try:
            result = _tail(guard_env, normative_scripts, seat)
            assert result.exit_code == 78, (
                f"{mutate}: expected UNSAFE exit 78, got {result.exit_code}"
            )
            assert "SECRETLOGDATA" not in result.stdout, "unsafe read leaked content"
        finally:
            session.run(restore)

    # Ownership: the logs directory owned by root (not the fixture user)
    # must also exit 78. Root-level chown via the docker control channel.
    uid = _fixture_uid(guard_env)
    session.run_as_root("chown 0:0 /home/fixture/.testudo/logs")
    try:
        result = _tail(guard_env, normative_scripts, seat)
        assert result.exit_code == 78, (
            f"root-owned logs dir: expected exit 78, got {result.exit_code}"
        )
        assert "SECRETLOGDATA" not in result.stdout
    finally:
        session.run_as_root(f"chown {uid}:{uid} /home/fixture/.testudo/logs")
    # and the file itself
    session.run_as_root(f"chown 0:0 /home/fixture/.testudo/logs/{seat}.log")
    try:
        result = _tail(guard_env, normative_scripts, seat)
        assert result.exit_code == 78, (
            f"root-owned log file: expected exit 78, got {result.exit_code}"
        )
    finally:
        session.run_as_root(f"chown {uid}:{uid} /home/fixture/.testudo/logs/{seat}.log")
    # restored: the happy path works again
    assert _tail(guard_env, normative_scripts, seat).exit_code == 0


@pytest.mark.usefixtures("linux_only")
def test_g9_rejects_symlinks(guard_env: GuardEnv, normative_scripts: dict[str, str]) -> None:
    """A symlinked logs directory or log file is rejected with exit 78 and
    never followed."""
    seat = "g9-symlink"
    session = guard_env.session()
    _reset_logs(guard_env, seat)
    session.run("mkdir -p -m 700 ~/alt-logs-target")
    session.run(f"printf 'DECOYDATA\\n' > ~/alt-logs-target/{seat}.log")

    # 1. ~/.testudo/logs replaced by a symlink to the decoy directory.
    session.run(
        "mv ~/.testudo/logs ~/.testudo/logs.real && ln -s ~/alt-logs-target ~/.testudo/logs"
    )
    try:
        result = _tail(guard_env, normative_scripts, seat)
        assert result.exit_code == 78, (
            f"symlinked logs dir: expected exit 78, got {result.exit_code}"
        )
        assert "DECOYDATA" not in result.stdout, "symlinked directory was followed"
    finally:
        session.run("rm -f ~/.testudo/logs && mv ~/.testudo/logs.real ~/.testudo/logs")

    # 2. The log file itself replaced by a symlink to a decoy file.
    session.run(
        f"rm -f ~/.testudo/logs/{seat}.log && ln -s ~/alt-logs-target/{seat}.log ~/.testudo/logs/{seat}.log"
    )
    try:
        result = _tail(guard_env, normative_scripts, seat)
        assert result.exit_code == 78, (
            f"symlinked log file: expected exit 78, got {result.exit_code}"
        )
        assert "DECOYDATA" not in result.stdout, "symlinked file was followed"
    finally:
        session.run(f"rm -f ~/.testudo/logs/{seat}.log ~/alt-logs-target/{seat}.log")


@pytest.mark.usefixtures("linux_only")
def test_g9_missing_log_file_fails_closed(
    guard_env: GuardEnv, normative_scripts: dict[str, str]
) -> None:
    """A log that does not exist (or a non-file) exits 78 — `[ -f ] && [ ! -L ]`."""
    session = guard_env.session()
    _reset_logs(guard_env, "g9-missing")
    result = _tail(guard_env, normative_scripts, "g9-missing")
    assert result.exit_code == 78, f"missing log: expected 78, got {result.exit_code}"
    # a directory at the log path is not a regular file either
    session.run("mkdir -p -m 700 ~/.testudo/logs/g9-missing.log")
    try:
        result = _tail(guard_env, normative_scripts, "g9-missing")
        assert result.exit_code == 78
    finally:
        session.run("rmdir ~/.testudo/logs/g9-missing.log")
