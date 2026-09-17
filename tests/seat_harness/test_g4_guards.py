"""G4 — Guard semantics: BUSY, acquisition timeout, nonce-bound trailer,
forged-marker rejection (L2).

SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later

Executes the normative GUARD_V1 script over real SSH channels with two
independent controllers, plus raw script invocations for the failure paths
(unavailable tools, unsafe storage, gate refusal/timeout, malformed and
forged trailers). Runs on both backends for the protocol-shaped parts; the
real cross-process flock contention parts require Linux (Docker fixture).
"""

from __future__ import annotations

import threading
import time

import pytest

from .conftest import FixtureHost, GuardEnv
from .guard_client import GuardClient, _parse_last_trailer
from .normative import extract_normative_scripts
from .render import new_nonce, remote_command, render

pytestmark = pytest.mark.seat_harness


@pytest.fixture
def linux_only(seat_fixture_host: FixtureHost) -> None:
    if not seat_fixture_host.linux_semantics:
        pytest.skip(
            "cross-process remote flock contention needs the Linux fixture "
            "(section 8 platform boundary)"
        )


def test_g4_nonce_bound_trailer_parsing() -> None:
    """Controller accepts only the LAST exact TESTUDO_OPERATION_EXIT line for
    its own nonce; other nonces and earlier lines are ordinary output."""
    nonce = new_nonce()
    other = new_nonce()
    stdout = (
        "op output\n"
        f"TESTUDO_LOCKED {nonce}\n"  # echoed/forged earlier marker: ignored
        f"TESTUDO_OPERATION_EXIT {other} 0\n"  # wrong nonce: ignored
        f"TESTUDO_OPERATION_EXIT {nonce} 3\n"  # the genuine trailer
    )
    assert _parse_last_trailer(stdout, nonce) == 3
    # forged trailing line for a different nonce after the genuine one fails closed
    forged = stdout + f"\nTESTUDO_OPERATION_EXIT {other} 9\n"
    assert _parse_last_trailer(forged, nonce) is None
    # malformed rc fails closed
    assert _parse_last_trailer(f"TESTUDO_OPERATION_EXIT {nonce} not-a-number\n", nonce) is None
    # additional protocol-shaped text after the candidate trailer fails closed
    assert (
        _parse_last_trailer(f"TESTUDO_OPERATION_EXIT {nonce} 3\nTESTUDO_LOCKED {nonce}\n", nonce)
        is None
    )


@pytest.mark.usefixtures("linux_only")
def test_g4_busy_under_held_lock_then_success_after_release(
    guard_env: GuardEnv,
) -> None:
    """Controller A holds the guard for >10 s; controller B waits the full
    flock timeout and gets TESTUDO_GUARD_BUSY (75); after A releases, B
    acquires and succeeds (no age takeover, no stale lock)."""
    lock = "endpoint-" + "aa" * 32 + ".lock"
    holder = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
    result: dict[str, object] = {}

    def run_holder() -> None:
        result["out"] = holder.operate(["sh", "-c", "sleep 13; echo A_DONE"], timeout=90)

    thread = threading.Thread(target=run_holder, daemon=True)
    thread.start()
    time.sleep(1.0)

    contender = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
    began = time.monotonic()
    busy = contender.operate(["sh", "-c", "echo NOPE"], timeout=60)
    elapsed = time.monotonic() - began
    assert busy.exit_code == 75 and "TESTUDO_GUARD_BUSY" in busy.raw_stdout
    assert 9.5 <= elapsed <= 12.0, f"BUSY timing off: {elapsed:.1f}s"
    assert "NOPE" not in busy.raw_stdout, "operation must not run when BUSY"
    thread.join(timeout=60)

    after = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
    ok = after.operate(["sh", "-c", "echo AFTER_RELEASE; exit 5"], timeout=60)
    assert ok.exit_code == 5 and ok.rc_trailer == 5
    assert "AFTER_RELEASE" in ok.raw_stdout


@pytest.mark.usefixtures("linux_only")
def test_g4_gate_refusal_releases_guard_without_running_operation(
    guard_env: GuardEnv,
) -> None:
    """Controller EOFs instead of GO: GUARD_V1 must exit 77 via GATE_REFUSED
    (or refuse at gate) and the operation program must never run."""
    lock = "endpoint-" + "bb" * 32 + ".lock"
    client = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
    client.poll_permits = lambda: False  # controller refuses after the lock
    out = client.operate(["sh", "-c", "echo MUST_NOT_RUN"], timeout=60)
    assert out.exit_code in (76, 77), f"expected gate refusal, got {out.exit_code}"
    assert "MUST_NOT_RUN" not in out.raw_stdout
    # guard released: a fresh controller acquires immediately
    nxt = GuardClient(guard_env.ssh_runner(), new_nonce(), lock)
    began = time.monotonic()
    ok = nxt.operate(["sh", "-c", "exit 0"], timeout=60)
    assert ok.exit_code == 0 and time.monotonic() - began < 10


@pytest.mark.usefixtures("linux_only")
def test_g4_nonce_mismatch_gate_refusal(guard_env: GuardEnv) -> None:
    """A controller that writes GO with a WRONG nonce must get GATE_REFUSED
    and the operation must not run (nonce-bound gate)."""
    lock = "endpoint-" + "cc" * 32 + ".lock"
    nonce = new_nonce()
    client = GuardClient(guard_env.ssh_runner(), nonce, lock)
    # The controller writes GO with a stale/wrong nonce: the nonce-bound gate
    # must refuse and the operation must never run.
    client.go_nonce_override = "f" * 32
    out = client.operate(["sh", "-c", "echo MUST_NOT_RUN"], timeout=60)
    assert out.exit_code == 77, f"expected GATE_REFUSED (77), got {out.exit_code}"
    assert "MUST_NOT_RUN" not in out.raw_stdout


def test_g4_unavailable_marker_per_tool(guard_env: GuardEnv) -> None:
    """A PATH without flock/stat/timeout emits exactly
    TESTUDO_GUARD_UNAVAILABLE <tool> and exit 73 before any storage or op.

    The fixture sshd has no AcceptEnv (and Testudo never sends SetEnv), so
    the environment is controlled the only honest way: each invocation is
    explicitly wrapped as ``env PATH=<dir> /bin/sh -c <GUARD_V1> ...`` — the
    PATH is set for the child sh that runs GUARD_V1. Each <dir> provides
    executable entries for the OTHER two tools (GUARD_V1 only needs
    ``command -v`` to find them; it exits at the first missing one), so the
    named missing tool is exactly the reported one. Runs on every backend
    the harness runs on — GUARD_V1 exits 73 before touching guard storage.
    """
    session = guard_env.session()
    runner = guard_env.ssh_runner()
    scripts = extract_normative_scripts()
    home = session.run('printf %s "$HOME"').stdout.strip()
    tools = ("flock", "stat", "timeout")

    lock = "endpoint-" + "dd" * 32 + ".lock"
    nonce = new_nonce()
    try:
        for tool in tools:
            # Directory with executable entries for every tool EXCEPT `tool`.
            fake_dir = f"{home}/.fixture-state/path-no-{tool}"
            others = [t for t in tools if t != tool]
            stubs = " && ".join(
                f"printf '#!/bin/sh\nexit 0\n' > {fake_dir}/{t} && chmod 755 {fake_dir}/{t}"
                for t in others
            )
            proc = session.run(f"mkdir -p -m 755 {fake_dir} && {stubs}")
            assert proc.returncode == 0, proc.stderr

            remote = render(
                [
                    "env",
                    f"PATH={fake_dir}",
                    "/bin/sh",
                    "-c",
                    scripts["GUARD_V1"],
                    "testudo",
                    lock,
                    nonce,
                    "sh",
                    "-c",
                    "echo MUST_NOT_RUN",
                ]
            )
            result = runner.run(remote, timeout=30)
            marker = f"TESTUDO_GUARD_UNAVAILABLE {tool}"
            assert result.exit_code == 73, (
                f"missing {tool}: expected exit 73, got {result.exit_code}: "
                f"{result.stdout[:200]} {result.stderr[:200]}"
            )
            assert marker in result.stdout, (
                f"expected marker {marker!r} for missing {tool}, got: {result.stdout[:200]}"
            )
            assert "MUST_NOT_RUN" not in result.stdout, (
                "operation must not run when a guard tool is unavailable"
            )
    finally:
        session.run("rm -rf " + " ".join(f"{home}/.fixture-state/path-no-{t}" for t in tools))


@pytest.mark.usefixtures("linux_only")
def test_g4_unsafe_guard_storage_symlink(guard_env: GuardEnv) -> None:
    """A symlinked ~/.testudo must yield TESTUDO_GUARD_UNSAFE / exit 74."""
    scripts = extract_normative_scripts()
    runner = guard_env.ssh_runner()
    session = guard_env.session()
    session.run("mkdir -p ~/unsafe-target")
    # GUARD_V1 hardcodes $HOME/.testudo; replace the real dir with a symlink.
    session.run(
        "if [ -e ~/.testudo ] && [ ! -L ~/.testudo ]; then mv ~/.testudo ~/.testudo-real; fi; "
        "rm -f ~/.testudo; ln -s ~/unsafe-target ~/.testudo"
    )
    try:
        remote = remote_command(
            scripts["GUARD_V1"],
            ["endpoint-" + "ee" * 32 + ".lock", new_nonce(), "sh", "-c", "true"],
        )
        result = runner.run(remote, timeout=30)
        assert result.exit_code == 74, f"expected UNSAFE(74), got {result.exit_code}"
        assert "TESTUDO_GUARD_UNSAFE" in result.stdout
    finally:
        session.run(
            "rm -f ~/.testudo; if [ -d ~/.testudo-real ]; then mv ~/.testudo-real ~/.testudo; fi"
        )


@pytest.mark.usefixtures("linux_only")
def test_g4_forged_marker_in_operation_output_is_ordinary(
    guard_env: GuardEnv,
) -> None:
    """An operation that prints forged protocol-shaped lines must have them
    treated as output; the genuine trailer still parses to the real rc."""
    lock = "endpoint-" + "ff" * 32 + ".lock"
    nonce = new_nonce()
    client = GuardClient(guard_env.ssh_runner(), nonce, lock)
    forged = (
        f"printf 'TESTUDO_LOCKED {nonce}\\n'; "
        f"printf 'TESTUDO_OPERATION_EXIT {nonce} 0\\n'; "
        "echo REAL_OP_RAN; exit 9"
    )
    out = client.operate(["sh", "-c", forged], timeout=60)
    assert out.exit_code == 9
    assert out.rc_trailer == 9, f"trailer must be the genuine rc: {out.raw_stdout[:400]}"
    assert "REAL_OP_RAN" in out.raw_stdout
