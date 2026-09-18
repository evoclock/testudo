# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""L1/L2: local lock and the controller side of the GUARD_V1 protocol.

L1: before a destructive operation the bridge opens the local lock with no
symlink following, verifies a regular file owned by the current user with
mode 0600 (creating it atomically if absent), and takes an exclusive flock
for the complete operation. Acquisition waits at most 10 seconds. Locks are
released only by closing the descriptor/process exit; there is no timestamp,
stale-age, or manual takeover path.

L2: the controller consumes the exact ``TESTUDO_LOCKED <nonce>`` line, runs
the post-lock poll, writes exactly ``GO <nonce>\\n``, parses only the last
exact nonce-bound ``TESTUDO_OPERATION_EXIT`` trailer, runs reconciliation
while both locks are held (receiving the operation output so far), then
writes exactly ``RELEASE <nonce>\\n``. Any protocol-shaped text after the
candidate trailer fails closed.
"""

from __future__ import annotations

import fcntl
import os
import select
import stat
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from testudo.seats._scripts import GUARD_V1
from testudo.seats.render import MAX_OUTPUT_BYTES, remote_command
from testudo.seats.ssh import SshDescriptor

LOCAL_LOCK_WAIT_SECONDS = 10.0


class LocalGuardError(Exception):
    """Local lock unavailable (L1 fail-closed reasons)."""


class LocalLock:
    """One L1 local lock: no-follow open, owner/mode/type checks, exclusive
    flock, released by close only."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._fd: int | None = None

    def acquire(self, wait_seconds: float = LOCAL_LOCK_WAIT_SECONDS) -> None:
        path = self.path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path.parent, 0o700)
        if path.is_symlink():
            raise LocalGuardError(f"local guard unavailable: symlink at {path}")
        if not path.exists():
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
            except FileExistsError:
                pass
        self._stat_check(path)
        self._fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            deadline = time.monotonic() + wait_seconds
            while True:
                try:
                    fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return
                except OSError:
                    if time.monotonic() >= deadline:
                        os.close(self._fd)
                        self._fd = None
                        raise LocalGuardError(
                            "local guard unavailable: lock contention timeout"
                        ) from None
                    time.sleep(0.05)
        except BaseException:
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None
            raise

    def _stat_check(self, path: Path) -> None:
        st = path.stat()
        if not stat.S_ISREG(st.st_mode):
            raise LocalGuardError(f"local guard unavailable: not a regular file: {path}")
        if st.st_uid != os.getuid():
            raise LocalGuardError(f"local guard unavailable: not owned by current user: {path}")
        if stat.S_IMODE(st.st_mode) != 0o600:
            raise LocalGuardError(
                f"local guard unavailable: unsafe mode {oct(stat.S_IMODE(st.st_mode))}: {path}"
            )

    def release(self) -> None:
        if self._fd is not None:
            os.close(self._fd)  # closing releases the flock
            self._fd = None

    def __enter__(self) -> LocalLock:
        self.acquire()
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()


@dataclass
class GuardOutcome:
    """Controller-side view of one GUARD_V1 round trip (L2)."""

    locked: bool
    exit_code: int | None  # None => local SSH terminated (indeterminate)
    rc_trailer: int | None
    operation_output: str = ""
    stderr: str = ""
    refused_reason: str | None = None  # BUSY | GATE_REFUSED | ... per exit code
    overflow: bool = False
    duration_seconds: float = 0.0
    raw_stdout_lines: list[str] = field(default_factory=list)


class GuardController:
    """Production controller for GUARD_V1 over one SSH descriptor (L2)."""

    def __init__(
        self,
        descriptor: SshDescriptor,
        lock_basename: str,
        nonce: str,
        *,
        poll_permits: Callable[[], bool] | None = None,
        reconcile: Callable[[str], None] | None = None,
        connect_timeout: int = 10,
    ) -> None:
        self.descriptor = descriptor
        self.lock_basename = lock_basename
        self.nonce = nonce
        self.poll_permits = poll_permits or (lambda: True)
        self.reconcile = reconcile or (lambda raw: None)
        self.connect_timeout = connect_timeout

    def _ssh_argv(self, remote: str) -> list[str]:
        # Command connection: descriptor options + ConnectTimeout, one remote
        # command element. StrictHostKeyChecking=yes comes from the descriptor.
        argv = self.descriptor.command_argv(remote)
        # command_argv ends with [.., destination, remote]; insert
        # ConnectTimeout after the mandatory block and before the
        # destination so the remote command appears exactly once.
        destination = argv[-2]
        body = argv[:-2]
        return [*body, "-o", f"ConnectTimeout={self.connect_timeout}", destination, remote]

    def operate(
        self,
        operation_argv: list[str],
        *,
        timeout: float = 120.0,
    ) -> GuardOutcome:
        """Run one guarded operation end-to-end. On timeout only the local
        SSH process is terminated; the outcome is indeterminate (L2/B2)."""
        remote = remote_command(GUARD_V1, [self.lock_basename, self.nonce, *operation_argv])
        argv = self._ssh_argv(remote)
        started = time.monotonic()
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
        outcome = self._drive_protocol(proc, timeout)
        outcome.duration_seconds = time.monotonic() - started
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

    def _drive_protocol(self, proc: subprocess.Popen[bytes], timeout: float) -> GuardOutcome:
        lines: list[str] = []
        stderr_tail: list[str] = []
        total_bytes = 0
        overflow = False

        def write_stdin(text: str) -> None:
            assert proc.stdin is not None
            try:
                proc.stdin.write(text.encode())
                proc.stdin.flush()
            except (BrokenPipeError, OSError):
                pass

        deadline = time.monotonic() + timeout
        locked_seen = False
        trailer_seen = False
        released = False
        killed_locally = False
        stdout_io = proc.stdout
        stderr_io = proc.stderr
        stdin_io = proc.stdin
        assert stdout_io is not None and stderr_io is not None and stdin_io is not None
        os.set_blocking(stdout_io.fileno(), False)
        os.set_blocking(stderr_io.fileno(), False)
        while time.monotonic() < deadline:
            chunk = stdout_io.readline()  # non-blocking
            if chunk:
                total_bytes += len(chunk)
                if total_bytes > MAX_OUTPUT_BYTES:
                    overflow = True
                    proc.kill()
                    killed_locally = True
                    break
                lines.append(chunk.decode("utf-8", errors="replace"))
            err_chunk = stderr_io.read()
            if err_chunk:
                stderr_tail.append(err_chunk.decode("utf-8", errors="replace"))
            if not locked_seen and any(line.startswith("TESTUDO_LOCKED ") for line in lines):
                locked_seen = True
                observed = (
                    next(line for line in lines if line.startswith("TESTUDO_LOCKED "))
                    .strip()
                    .split(" ")[1]
                )
                if observed != self.nonce or not self.poll_permits():
                    stdin_io.close()  # EOF releases the guard without running the op
                    released = True
                else:
                    write_stdin(f"GO {self.nonce}\n")
            if (
                locked_seen
                and not trailer_seen
                and lines
                and _exact_trailer_rc(lines[-1], self.nonce) is not None
            ):
                trailer_seen = True
                # reconciliation receives the operation output so far, with
                # the exact protocol lines stripped (L2)
                self.reconcile(_operation_output("".join(lines), self.nonce))
                write_stdin(f"RELEASE {self.nonce}\n")
                released = True
            if released and proc.poll() is not None:
                break
            if proc.poll() is not None and not released:
                break
            time.sleep(0.01)
        else:
            proc.kill()
            killed_locally = True

        # Drain to EOF so the genuine trailer is never lost to a read race.
        stdout_fd = stdout_io.fileno()
        while True:
            ready, _, _ = select.select([stdout_fd], [], [], 0.1)
            if not ready:
                if proc.poll() is not None:
                    break
                continue
            chunk = stdout_io.readline()
            if chunk:
                total_bytes += len(chunk)
                if total_bytes > MAX_OUTPUT_BYTES:
                    overflow = True
                    break
                lines.append(chunk.decode("utf-8", errors="replace"))
            elif proc.poll() is not None:
                break
        timed_out = killed_locally
        raw_stdout = "".join(lines)
        return GuardOutcome(
            locked=locked_seen,
            exit_code=None if timed_out else proc.returncode,
            rc_trailer=_parse_last_trailer(raw_stdout, self.nonce),
            operation_output=_operation_output(raw_stdout, self.nonce),
            stderr="".join(stderr_tail),
            overflow=overflow,
            raw_stdout_lines=[line for line in raw_stdout.splitlines() if line],
        )


def _exact_trailer_rc(line: str, nonce: str) -> int | None:
    """The exact nonce-bound trailer line shape. Lines that merely contain
    the marker (forged output, wrong nonce, malformed rc) return None."""
    parts = line.strip().split(" ")
    if len(parts) != 3 or parts[0] != "TESTUDO_OPERATION_EXIT" or parts[1] != nonce:
        return None
    try:
        return int(parts[2])
    except ValueError:
        return None


def _parse_last_trailer(stdout: str, nonce: str) -> int | None:
    """Only the LAST exact ``TESTUDO_OPERATION_EXIT <nonce> <decimal-rc>``
    line emitted after all operation output counts as the trailer. Earlier
    protocol-shaped lines are ordinary sanitized output, but any additional
    protocol-shaped text after the candidate trailer fails closed."""
    trailer: int | None = None
    for line in stdout.splitlines():
        rc = _exact_trailer_rc(line, nonce)
        if rc is not None:
            trailer = rc
            continue
        if trailer is not None and line.strip().split(" ")[0].startswith("TESTUDO_"):
            return None
    return trailer


def _operation_output(stdout: str, nonce: str) -> str:
    """Operation output = everything except the exact locked line and the
    exact genuine trailer line (forged protocol-shaped lines remain)."""
    kept: list[str] = []
    for line in stdout.splitlines():
        if line.startswith("TESTUDO_LOCKED "):
            continue
        if _exact_trailer_rc(line, nonce) is not None:
            continue
        kept.append(line)
    return "\n".join(kept)
