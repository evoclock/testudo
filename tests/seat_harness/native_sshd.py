"""Native (non-Docker) disposable sshd fixture for macOS development.

SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later

Spec section 8 asks for a disposable local sshd on a loopback port. On the
macOS dev machine (where Docker may be present but Linux-only semantics such
as ``flock``/``setsid``/``/proc`` are not) this module still provides a real
OpenSSH server on 127.0.0.1 so that the *SSH-transport-shaped* parts of the
harness (quoting round-trips, guard protocol framing, ssh -G shim resolution)
execute against a genuine sshd.

Platform limitation (documented, per section 8): macOS lacks Linux /proc,
util-linux setsid, GNU stat -c semantics differ, and there is no cross-
process POSIX flock on regular files in the GUARD_V1 sense. Therefore:

* G1/G2 (LAUNCH_V1, C_PID_V1, FD 9 non-inheritance, PGID escalation) run in
  the Linux Docker fixture; they are skipped with an explicit reason on the
  macOS fallback (the Docker path is exercised on Linux CI and locally when
  Docker is available).
* G3/G4/G7/G8 (quoting, guard protocol framing over a real SSH channel,
  loginctl shims, ssh -G consent drift) run on both platforms.

The server is a per-session ``/usr/sbin/sshd -D`` on a loopback port with a
dedicated host key, a dedicated fixture user record is NOT created (macOS
sshd requires an actual local user; we instead authorize the *current*
user's dedicated fixture key, exercising the same pubkey path). All state
lives under a pytest tmp directory and is removed afterwards.
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path

SSHD_BINARY = "/usr/sbin/sshd"


class NativeSshdError(RuntimeError):
    """Raised when the native macOS sshd fixture cannot start."""


class NativeSshd:
    """A disposable per-session sshd on 127.0.0.1 (macOS fallback)."""

    def __init__(self, state_dir: Path, port: int | None = None) -> None:
        self.state_dir = state_dir
        self.port = port or self._free_port()
        self.username = os.environ["USER"]
        self._proc: subprocess.Popen[bytes] | None = None

    @staticmethod
    def available() -> bool:
        """True when the native sshd binary exists (macOS fallback support)."""
        return Path(SSHD_BINARY).exists()

    @staticmethod
    def _free_port() -> int:
        import socket

        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return int(s.getsockname()[1])

    def start(self) -> None:
        if not Path(SSHD_BINARY).exists():
            raise NativeSshdError(f"{SSHD_BINARY} not present")
        d = self.state_dir
        d.mkdir(parents=True, exist_ok=True)
        # Host key + user key (no passphrase).
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(d / "hostkey")],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(d / "userkey")],
            check=True,
            capture_output=True,
        )
        (d / "authorized_keys").write_bytes((d / "userkey.pub").read_bytes())
        config = f"""Port {self.port}
ListenAddress 127.0.0.1
HostKey {d}/hostkey
PidFile {d}/sshd.pid
AuthorizedKeysFile {d}/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM no
PermitRootLogin no
StrictModes no
Subsystem sftp internal-sftp
"""
        (d / "sshd_config").write_text(config)
        os.chmod(d / "authorized_keys", 0o600)
        self._proc = subprocess.Popen(
            [SSHD_BINARY, "-D", "-f", str(d / "sshd_config"), "-E", str(d / "sshd.log")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        if not self._wait_ready():
            self.stop()
            raise NativeSshdError("native sshd did not become ready in time")

    def _wait_ready(self, timeout: float = 15.0) -> bool:
        import socket

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._proc is not None and self._proc.poll() is not None:
                return False
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                    return True
            except OSError:
                time.sleep(0.1)
        return False

    def stop(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            os.killpg(self._proc.pid, signal.SIGTERM)
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(self._proc.pid, signal.SIGKILL)

    @property
    def user_key_path(self) -> Path:
        return self.state_dir / "userkey"

    @property
    def host_key_fingerprint(self) -> str:
        proc = subprocess.run(
            ["ssh-keygen", "-lf", str(self.state_dir / "hostkey.pub")],
            capture_output=True,
            text=True,
            check=True,
        )
        # "256 SHA256:xxxx comment (ED25519)"
        for field in proc.stdout.split():
            if field.startswith("SHA256:"):
                return field
        raise NativeSshdError("no SHA256 fingerprint in ssh-keygen output")
