"""SSH runner and the reference L2 guard client (controller side).

SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later

``SshRunner`` executes one rendered remote command over a real SSH channel
with interactive stdin, bounded output, and a wall-clock timeout — the
transport-shaped boundary the spec's controller uses (local process
termination on timeout => indeterminate, B2).

``GuardClient`` is the reference implementation of the controller side of
the GUARD_V1 protocol: consume the exact ``TESTUDO_LOCKED <nonce>`` line,
write ``GO <nonce>\\n`` only after the post-lock poll permits, consume the
last exact ``TESTUDO_OPERATION_EXIT <nonce> <rc>`` trailer, then write
``RELEASE <nonce>\\n``. It is what G1/G4 exercise, byte-for-byte against the
normative script.
"""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

MAX_OUTPUT_BYTES = 1024 * 1024  # spec: hard 1 MiB read cap


@dataclass
class CommandResult:
    exit_code: int | None  # None => local SSH terminated (indeterminate)
    stdout: str
    stderr: str
    timed_out: bool
    overflow: bool = False
    duration_seconds: float = 0.0


class SshRunner:
    """Runs rendered remote commands against a fixture sshd."""

    def __init__(
        self,
        destination: str,
        key_path: Path,
        port: int,
        known_hosts: Path,
        *,
        connect_timeout: float = 10.0,
    ) -> None:
        self.destination = destination
        self.key_path = key_path
        self.port = port
        self.known_hosts = known_hosts
        self.connect_timeout = connect_timeout

    def argv(self, remote_command: str, *, extra_options: list[str] | None = None) -> list[str]:
        options = [
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-i",
            str(self.key_path),
            "-p",
            str(self.port),
            "-o",
            f"ConnectTimeout={int(self.connect_timeout)}",
            "-o",
            "StrictHostKeyChecking=no",  # harness fixture host only
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "RemoteCommand=none",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ForwardX11=no",
            "-o",
            "RequestTTY=no",
            *(extra_options or []),
        ]
        return ["ssh", *options, self.destination, remote_command]

    def run(
        self,
        remote_command: str,
        *,
        stdin_bytes: bytes | None = None,
        stdin_writer: Callable[[subprocess.Popen[bytes]], None] | None = None,
        timeout: float = 60.0,
        output_cap: int = MAX_OUTPUT_BYTES,
        extra_options: list[str] | None = None,
    ) -> CommandResult:
        started = time.monotonic()
        proc = subprocess.Popen(
            self.argv(remote_command, extra_options=extra_options),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        timed_out = False
        try:
            if stdin_writer is not None:
                assert proc.stdin is not None
                stdin_writer(proc)
                proc.stdin.close()
            elif stdin_bytes is not None:
                assert proc.stdin is not None
                proc.stdin.write(stdin_bytes)
                proc.stdin.close()
            else:
                if proc.stdin is not None:
                    proc.stdin.close()
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            out, err = proc.communicate()
        duration = time.monotonic() - started
        stdout = out.decode("utf-8", errors="replace") if out else ""
        stderr = err.decode("utf-8", errors="replace") if err else ""
        overflow = len(out or b"") > output_cap or len(err or b"") > output_cap
        return CommandResult(
            exit_code=None if timed_out else proc.returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            overflow=overflow,
            duration_seconds=duration,
        )


@dataclass
class GuardOutcome:
    """Controller-side view of one GUARD_V1 round trip."""

    locked: bool
    exit_code: int | None
    rc_trailer: int | None  # parsed operation exit code from the genuine trailer
    stdout_lines: list[str] = field(default_factory=list)
    stderr: str = ""
    raw_stdout: str = ""
    refused_reason: str | None = None  # BUSY | GATE_REFUSED | GATE_TIMEOUT | ...
    duration_seconds: float = 0.0


class GuardClient:
    """Reference controller for the GUARD_V1 protocol (L2).

    The protocol loop reads GUARD_V1's stdout line-by-line while stdin stays
    open, writes ``GO <nonce>`` only after the post-lock poll permits, waits
    for the operation trailer, runs reconciliation while both locks are
    held, then writes ``RELEASE <nonce>``. All writes/reads happen on the
    same local SSH process, mirroring the spec's controller exactly.
    """

    def __init__(self, runner: SshRunner, nonce: str, lock_basename: str) -> None:
        self.runner = runner
        self.nonce = nonce
        self.lock_basename = lock_basename
        # Test hook: when set, the controller writes GO with this (wrong) nonce
        # while the gate still expects the original — nonce-mismatch sabotage.
        self.go_nonce_override: str | None = None
        # Post-lock poll hook: controller decides GO/EOF after both locks.
        self.poll_permits: Callable[[], bool] = lambda: True
        # Reconciliation hook executed while both locks are held, before RELEASE.
        self.reconcile: Callable[[], None] = lambda: None

    def operate(
        self,
        operation_argv: list[str],
        *,
        timeout: float = 120.0,
    ) -> GuardOutcome:
        """Run one guarded operation end-to-end."""
        remote = render_guard_invocation(self.lock_basename, self.nonce, operation_argv)
        argv = self.runner.argv(remote)
        started = time.monotonic()
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        assert proc.stdout is not None and proc.stdin is not None
        outcome = _drive_protocol_full(
            proc,
            self.nonce,
            self.poll_permits,
            self.reconcile,
            timeout,
            self.go_nonce_override,
        )
        outcome.duration_seconds = time.monotonic() - started
        outcome.stdout_lines = [line for line in outcome.raw_stdout.splitlines() if line]
        if outcome.exit_code == 75:
            outcome.refused_reason = "BUSY"
        elif outcome.exit_code == 77:
            outcome.refused_reason = "GATE_REFUSED"
        elif outcome.exit_code == 76:
            outcome.refused_reason = "GATE_TIMEOUT"
        elif outcome.exit_code == 73:
            outcome.refused_reason = "UNAVAILABLE"
        elif outcome.exit_code == 74:
            outcome.refused_reason = "UNSAFE"
        return outcome


def _drive_protocol_full(
    proc: subprocess.Popen[bytes],
    nonce: str,
    poll_permits: Callable[[], bool],
    reconcile: Callable[[], None],
    timeout: float,
    go_nonce_override: str | None = None,
) -> GuardOutcome:
    """Interleaved stdout-read / stdin-write protocol loop (single reader)."""
    assert proc.stdout is not None and proc.stdin is not None
    lines: list[str] = []
    stderr_tail: list[str] = []

    def write_stdin(text: str) -> None:
        assert proc.stdin is not None
        proc.stdin.write(text.encode())
        proc.stdin.flush()

    deadline = time.monotonic() + timeout
    locked_seen = False
    trailer_seen = False
    released = False
    killed_locally = False
    assert proc.stdout is not None and proc.stderr is not None
    os.set_blocking(proc.stdout.fileno(), False)
    os.set_blocking(proc.stderr.fileno(), False)
    while time.monotonic() < deadline:
        chunk = proc.stdout.readline()  # non-blocking
        if chunk:
            lines.append(chunk.decode("utf-8", errors="replace"))
        err_chunk = proc.stderr.read()
        if err_chunk:
            stderr_tail.append(err_chunk.decode("utf-8", errors="replace"))
        if not locked_seen and any(line.startswith("TESTUDO_LOCKED ") for line in lines):
            locked_seen = True
            observed = (
                next(line for line in lines if line.startswith("TESTUDO_LOCKED "))
                .strip()
                .split(" ")[1]
            )
            if observed != nonce or not poll_permits():
                proc.stdin.close()  # EOF releases the guard without running the op
                released = True
            else:
                go_nonce = go_nonce_override or nonce
                write_stdin(f"GO {go_nonce}\n")
        if locked_seen and not trailer_seen and _exact_trailer_rc(lines[-1], nonce) is not None:
            trailer_seen = True
            reconcile()
            write_stdin(f"RELEASE {nonce}\n")
            released = True
        if released and proc.poll() is not None:
            break
        # drain remaining output after process exit
        if proc.poll() is not None and not released:
            # process died without trailer (e.g. BUSY exit path)
            break
        time.sleep(0.01)
    else:
        proc.kill()
        killed_locally = True

    # Drain to EOF non-blocking, distinguishing EAGAIN (no data yet) from
    # process exit so the genuine trailer is never lost to a read race.
    import select

    assert proc.stdout is not None
    stdout_fd = proc.stdout.fileno()
    while True:
        ready, _, _ = select.select([stdout_fd], [], [], 0.1)
        if not ready:
            if proc.poll() is not None:
                break
            continue
        chunk = proc.stdout.readline()
        if chunk:
            lines.append(chunk.decode("utf-8", errors="replace"))
        elif proc.poll() is not None:
            break
    timed_out = killed_locally
    raw_stdout = "".join(lines)
    return GuardOutcome(
        locked=locked_seen,
        exit_code=None if timed_out else proc.returncode,
        rc_trailer=_parse_last_trailer(raw_stdout, nonce),
        raw_stdout=raw_stdout,
        stderr="".join(stderr_tail),
    )


def render_guard_invocation(lock_basename: str, nonce: str, operation_argv: list[str]) -> str:
    """Render the full guarded local SSH remote-command string (C2)."""
    from .render import remote_command

    guard_script = _load_guard_script()
    return remote_command(guard_script, [lock_basename, nonce, *operation_argv])


_GUARD_SCRIPT_CACHE: str | None = None


def _load_guard_script() -> str:
    global _GUARD_SCRIPT_CACHE
    if _GUARD_SCRIPT_CACHE is None:
        from .normative import extract_normative_scripts

        _GUARD_SCRIPT_CACHE = extract_normative_scripts()["GUARD_V1"]
    return _GUARD_SCRIPT_CACHE


def _parse_last_trailer(stdout: str, nonce: str) -> int | None:
    """Controller trailer rule (L2): only the LAST exact
    TESTUDO_OPERATION_EXIT <nonce> <decimal-rc> line emitted after all
    operation output counts as the trailer. Earlier protocol-shaped lines
    (locked/exit markers, any nonce) are ordinary sanitized output, but ANY
    additional protocol-shaped text after the candidate trailer fails closed
    (returns None)."""
    trailer: int | None = None
    for line in stdout.splitlines():
        rc = _exact_trailer_rc(line, nonce)
        if rc is not None:
            trailer = rc
            continue
        if trailer is not None and line.strip().split(" ")[0].startswith("TESTUDO_"):
            return None  # protocol-shaped text after the candidate trailer
    return trailer


def _exact_trailer_rc(line: str, nonce: str) -> int | None:
    """The exact nonce-bound trailer line shape, shared by the stream loop
    (RELEASE trigger) and _parse_last_trailer: the complete line must be
    TESTUDO_OPERATION_EXIT <nonce> <decimal-rc>. Lines that merely contain
    the marker (forged operation output, wrong nonce, malformed rc) return
    None and stay ordinary output."""
    parts = line.strip().split(" ")
    if len(parts) != 3 or parts[0] != "TESTUDO_OPERATION_EXIT" or parts[1] != nonce:
        return None
    try:
        return int(parts[2])
    except ValueError:
        return None  # malformed protocol-shaped text fails closed
