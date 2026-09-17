# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""S1/S2 SSH identity, effective-configuration resolution, and host-key trust.

One immutable invocation descriptor per host. ``ssh -G`` is run by local
spawn with shell:false, the same descriptor, ``-G`` before the destination,
an empty stdin, a 10-second timeout, and a 1 MiB output cap. The canonical
effective value binds the complete ordered ``(key, value)`` sequence plus
the real path, version string, and SHA-256 hash of all bytes of the selected
``ssh`` binary.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from testudo.seats.render import MAX_OUTPUT_BYTES
from testudo.seats.validation import (
    ValidationError,
    canonical_hostname,
    validate_ssh_alias,
    validate_ssh_user,
)

RESOLVE_TIMEOUT_SECONDS = 10.0
PROBE_TIMEOUT_SECONDS = 10.0
EXEC_DEFAULT_TIMEOUT = 30.0

# Mandatory command-line options, in order, placed before user-derived options.
MANDATORY_OPTIONS: tuple[str, ...] = (
    "BatchMode=yes",
    "StrictHostKeyChecking=yes",
    # UserKnownHostsFile is host-specific (Testudo-owned 0600 file).
    "GlobalKnownHostsFile=/dev/null",
    "PermitLocalCommand=no",
    "RemoteCommand=none",
    "ClearAllForwardings=yes",
    "ForwardAgent=no",
    "ForwardX11=no",
    "ForwardX11Trusted=no",
    "RequestTTY=no",
)


def mandatory_ssh_options(known_hosts_path: str | Path) -> list[str]:
    """The mandatory ``-o`` options for command connections (section 3.1)."""
    options: list[str] = []
    for option in MANDATORY_OPTIONS:
        if option == "StrictHostKeyChecking=yes":
            options.extend(["-o", option])
            options.extend(["-o", f"UserKnownHostsFile={known_hosts_path}"])
        else:
            options.extend(["-o", option])
    return options


@dataclass(frozen=True)
class SshDescriptor:
    """One immutable invocation descriptor for a host (section 3.1)."""

    destination: str  # validated alias, or validated user@host
    port: int | None  # explicit form only
    key_path: str | None  # explicit form only
    known_hosts_path: str

    @classmethod
    def from_config(cls, ssh: dict[str, object], known_hosts_path: str | Path) -> SshDescriptor:
        kind = ssh.get("kind")
        if kind == "alias":
            alias = validate_ssh_alias("ssh.alias", str(ssh["alias"]))
            return cls(alias, None, None, str(known_hosts_path))
        if kind == "explicit":
            user = validate_ssh_user("ssh.user", str(ssh["user"]))
            host = canonical_hostname("ssh.host", str(ssh["host"]))
            raw_port = ssh["port"]
            if not isinstance(raw_port, int) or isinstance(raw_port, bool):
                raise ValidationError("ssh.port", "type", "expected a JSON integer")
            port = raw_port
            key_path = ssh.get("key_path")
            return cls(
                f"{user}@{host}",
                port,
                str(key_path) if key_path is not None else None,
                str(known_hosts_path),
            )
        raise ValidationError("ssh.kind", "discriminator")

    def destination_args(self) -> list[str]:
        """User-derived options after the mandatory block, then destination."""
        args: list[str] = []
        if self.port is not None:
            args.extend(["-p", str(self.port)])
        if self.key_path is not None:
            args.extend(["-i", self.key_path])
        args.append(self.destination)
        return args

    def command_argv(self, remote_command: str) -> list[str]:
        """Local argv for one command connection (S1): mandatory options,
        user-derived options, destination, exactly one remote-command string."""
        return [
            "ssh",
            *mandatory_ssh_options(self.known_hosts_path),
            *self.destination_args(),
            remote_command,
        ]

    def resolve_argv(self) -> list[str]:
        """Local argv for ``ssh -G`` with the same descriptor."""
        return [
            "ssh",
            *mandatory_ssh_options(self.known_hosts_path),
            "-G",
            *self.destination_args()[:-1],
            self.destination,
        ]

    def probe_argv(self, temporary_known_hosts: str | Path) -> list[str]:
        """Local argv for the isolated no-command key probe (S2).

        The probe override options are placed before every ordinary
        descriptor ``-o`` option (OpenSSH uses the first obtained value);
        ``-N -T`` appears before the destination; no remote command.
        """
        probe_overrides: list[str] = []
        for option in (
            "StrictHostKeyChecking=accept-new",
            f"UserKnownHostsFile={temporary_known_hosts}",
            "GlobalKnownHostsFile=/dev/null",
            "HashKnownHosts=no",
            "ConnectionAttempts=1",
            "ConnectTimeout=10",
        ):
            probe_overrides.extend(["-o", option])
        destination_args = self.destination_args()
        destination = destination_args[-1]
        user_args = destination_args[:-1]
        return [
            "ssh",
            *probe_overrides,
            *mandatory_ssh_options(self.known_hosts_path),
            *user_args,
            "-N",
            "-T",
            destination,
        ]


@dataclass(frozen=True)
class EffectiveSsh:
    """The canonical effective SSH configuration (S1)."""

    ordered_pairs: tuple[tuple[str, str], ...]
    binary_path: str
    binary_version: str
    binary_sha256: str

    def canonical_json(self) -> str:
        return json.dumps(
            {
                "ordered_pairs": [list(pair) for pair in self.ordered_pairs],
                "binary_path": self.binary_path,
                "binary_version": self.binary_version,
                "binary_sha256": self.binary_sha256,
            },
            separators=(",", ":"),
            ensure_ascii=False,
        )

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


class SshResolveError(Exception):
    """``ssh -G`` failed closed (timeout, overflow, malformed, prompt, exit)."""


_LINE_RE_WARN = "warning"


def _parse_ssh_g_output(raw: bytes) -> tuple[tuple[str, str], ...]:
    """Parse ``ssh -G`` output: lines of ``lowercase-key SP value``; repeated
    keys preserve output order. Rejects NUL, control characters other than
    line endings, and empty/malformed lines."""
    if b"\x00" in raw:
        raise SshResolveError("NUL byte in ssh -G output")
    text = raw.decode("utf-8", errors="strict")
    pairs: list[tuple[str, str]] = []
    for line in text.splitlines():
        if not line:
            continue
        if any(ord(character) < 0x20 and character not in "\t" for character in line):
            raise SshResolveError("control character in ssh -G output")
        if line.lower().startswith("warning ") or line.lower().startswith("warning:"):
            # OpenSSH warnings on stderr only, but a stdout "warning" line is
            # not a key/value pair and fails closed.
            raise SshResolveError("warning line in ssh -G output")
        key, separator, value = line.partition(" ")
        if not separator or not key or not value:
            raise SshResolveError(f"malformed ssh -G line: {line!r}")
        if key != key.lower() and key != "canonicalizePermittedcnames":
            raise SshResolveError(f"uppercase key in ssh -G line: {line!r}")
        pairs.append((key, value))
    if not pairs:
        raise SshResolveError("empty ssh -G output")
    return tuple(pairs)


def _ssh_binary_info() -> tuple[str, str, str]:
    """Real path, version string, and SHA-256 of all bytes of the ssh binary."""
    path = shutil.which("ssh")
    if path is None:
        raise SshResolveError("ssh binary not found")
    real = os.path.realpath(path)
    data = Path(real).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    try:
        version = (
            subprocess.run(
                [real, "-V"],
                capture_output=True,
                shell=False,
                timeout=5,
                check=False,
            )
            .stderr.decode("utf-8", errors="replace")
            .strip()
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SshResolveError(f"ssh -V failed: {exc}") from exc
    return real, version, digest


def effective_user(effective: EffectiveSsh) -> str | None:
    """The remote account name from the resolved effective configuration
    (the ``user`` key of the complete ordered ``ssh -G`` parse)."""
    for key, value in effective.ordered_pairs:
        if key == "user":
            return value
    return None


@dataclass(frozen=True)
class ExecResult:
    """One read-only remote command execution (inspect/status/linger/log
    tail). ``exit_code`` is None when the local SSH process was terminated
    (timeout): the outcome is indeterminate, never success or error."""

    exit_code: int | None
    stdout: str
    stderr: str
    truncated: bool = False


def exec_remote(
    descriptor: SshDescriptor,
    remote: str,
    *,
    timeout: float = EXEC_DEFAULT_TIMEOUT,
    connect_timeout: int = 10,
) -> ExecResult:
    """Run one rendered remote command on a command connection with the
    same descriptor, a bounded wall clock, and the 1 MiB read cap. Remote
    stdout/stderr beyond the cap is kept only up to the cap and flagged."""
    argv = descriptor.command_argv(remote)
    destination = argv[-2]
    body = argv[:-2]
    body.extend(["-o", f"ConnectTimeout={connect_timeout}"])
    argv = [*body, destination, remote]
    try:
        proc = subprocess.run(
            argv,
            input=b"",
            capture_output=True,
            shell=False,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ExecResult(None, "", "local SSH terminated on timeout")
    except OSError as exc:
        return ExecResult(None, "", str(exc))
    truncated = len(proc.stdout) > MAX_OUTPUT_BYTES or len(proc.stderr) > MAX_OUTPUT_BYTES
    return ExecResult(
        proc.returncode,
        proc.stdout[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace"),
        proc.stderr[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace"),
        truncated,
    )


def resolve_effective_ssh(descriptor: SshDescriptor) -> EffectiveSsh:
    """Run ``ssh -G`` per S1: local spawn, shell:false, same descriptor,
    ``-G`` before the destination, empty stdin, 10 s timeout, 1 MiB cap."""
    argv = descriptor.resolve_argv()
    binary_path, binary_version, binary_sha256 = _ssh_binary_info()
    try:
        proc = subprocess.run(
            argv,
            input=b"",
            capture_output=True,
            shell=False,
            timeout=RESOLVE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise SshResolveError("ssh -G timed out") from exc
    except OSError as exc:
        raise SshResolveError(f"ssh -G spawn failed: {exc}") from exc
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace")[:512]
        raise SshResolveError(f"ssh -G exited {proc.returncode}: {stderr}")
    if len(proc.stdout) > MAX_OUTPUT_BYTES or len(proc.stderr) > MAX_OUTPUT_BYTES:
        raise SshResolveError("ssh -G output overflow")
    pairs = _parse_ssh_g_output(proc.stdout)
    return EffectiveSsh(pairs, binary_path, binary_version, binary_sha256)


# --- S2: isolated key probe --------------------------------------------------


@dataclass
class KeyProbeResult:
    known_hosts_line: str
    fingerprint: str


class KeyProbeError(Exception):
    """The key probe failed closed; no artifact is trusted."""


def probe_host_key(descriptor: SshDescriptor, data_dir: Path) -> KeyProbeResult:
    """Observe a host key without trusting it (S2).

    Creates a unique 0600 empty file in ``data_dir``, runs the probe argv
    (``-N -T`` sends no remote command, so a successful connection stays
    open), and watches for the one accepted artifact: exactly one nonempty
    known-hosts line written to the temporary file. When the line appears
    the bridge terminates the local process; a process exit before any
    line, or the 10-second bound, fails closed and the temporary file is
    deleted. Never modifies the trusted file.
    """
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp_name = tempfile.mkstemp(prefix="probe-", suffix=".kh", dir=data_dir)
    os.fchmod(fd, 0o600)
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        argv = descriptor.probe_argv(temp_path)
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
            )
        except OSError as exc:
            raise KeyProbeError(f"key probe spawn failed: {exc}") from exc
        deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
        line: str | None = None
        while time.monotonic() < deadline:
            written = [
                text
                for text in temp_path.read_text(encoding="utf-8", errors="replace").splitlines()
                if text.strip()
            ]
            if len(written) > 1:
                raise KeyProbeError(f"expected exactly one known-hosts line, got {len(written)}")
            if written:
                line = written[0].strip()
                break  # artifact observed: terminate the local process
            if proc.poll() is not None:
                # exited before writing a line: unreachable/refused/failed
                break
            time.sleep(0.05)
        # S2: the bridge terminates the local process after the probe; a
        # surviving process must never leak.
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
        if line is None or not line:
            raise KeyProbeError("no known-hosts line was observed before exit/timeout")
        fingerprint = _fingerprint_of_line(line, descriptor)
        return KeyProbeResult(line, fingerprint)
    finally:
        temp_path.unlink(missing_ok=True)


def _fingerprint_of_line(line: str, descriptor: SshDescriptor) -> str:
    """Local ``ssh-keygen -lf`` with shell:false; exactly one SHA256: line."""
    # Write the single line to a temp file for ssh-keygen (it takes a path).
    data_dir = Path(descriptor.known_hosts_path).parent
    fd, temp_name = tempfile.mkstemp(prefix="fp-", suffix=".kh", dir=data_dir)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(line + "\n")
    temp_path = Path(temp_name)
    try:
        try:
            proc = subprocess.run(
                ["ssh-keygen", "-lf", str(temp_path)],
                capture_output=True,
                shell=False,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise KeyProbeError(f"ssh-keygen failed: {exc}") from exc
        if proc.returncode != 0:
            raise KeyProbeError("ssh-keygen -lf exited nonzero")
        fingerprints = [
            part
            for part in proc.stdout.decode("utf-8", errors="replace").split()
            if part.startswith("SHA256:")
        ]
        if len(fingerprints) != 1:
            raise KeyProbeError(
                f"expected exactly one SHA256: fingerprint, got {len(fingerprints)}"
            )
        return fingerprints[0]
    finally:
        temp_path.unlink(missing_ok=True)


class HostKeyTrustStore:
    """The Testudo-owned known-hosts file in the 0700 data directory (S2)."""

    def __init__(self, path: Path) -> None:
        global _trust_store_context_descriptor
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)
        _trust_store_context_descriptor = SshDescriptor("localhost", None, None, str(self.path))

    def _read_lines(self) -> list[str]:
        try:
            return self.path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []

    def known_fingerprint(self, host: str, port: int | None) -> str | None:
        """The fingerprint of the trusted line for host[:port], if any."""
        for marker in _host_entry_markers(host, port):
            for line in self._read_lines():
                if line.startswith(marker):
                    fingerprint = _extract_fingerprint(line)
                    if fingerprint is not None:
                        return fingerprint
        return None

    def install_initial(self, line: str) -> None:
        """Atomically add exactly the bridge-observed line (initial trust)."""
        lines = self._read_lines()
        if line in lines:
            return
        _atomic_rewrite(self.path, [*lines, line])

    def replace_for_host(self, new_line: str, host: str, port: int | None) -> None:
        """Atomically rewrite so every prior line for the effective host and
        port is removed in the same rename that installs exactly the new
        observed line (S2 replacement trust)."""
        marker = _host_entry_prefix(host, port)
        kept = [line for line in self._read_lines() if not line.startswith(marker)]
        _atomic_rewrite(self.path, [*kept, new_line])

    def remove_host(self, host: str, port: int | None) -> None:
        marker = _host_entry_prefix(host, port)
        kept = [line for line in self._read_lines() if not line.startswith(marker)]
        _atomic_rewrite(self.path, kept)


def _host_entry_markers(host: str, port: int | None) -> tuple[str, ...]:
    """Known-hosts host-field markers for a host/port, both spellings."""
    if port is not None and port != 22:
        return (f"[{host}]:{port}", host)
    return (host,)


def _host_entry_prefix(host: str, port: int | None) -> str:
    # OpenSSH known_hosts host field for a non-default port is [host]:port.
    if port is not None and port != 22:
        return f"[{host}]:{port}"
    return host


def _extract_fingerprint(line: str) -> str | None:
    """The SHA256: fingerprint of a known-hosts line, computing it with
    ``ssh-keygen -lf`` when the line does not carry a marker comment."""
    parts = line.split()
    for part in parts:
        if part.startswith("SHA256:"):
            return part
    if _trust_store_context_descriptor is None:
        return None
    return _fingerprint_of_line(line, _trust_store_context_descriptor)


# Set by HostKeyTrustStore.__init__ so _extract_fingerprint can reach a
# scratch directory for ssh-keygen without threading a parameter through
# every read path.
_trust_store_context_descriptor: SshDescriptor | None = None


def _atomic_rewrite(path: Path, lines: list[str]) -> None:
    """Write the complete new file to a 0600 temp, rename atomically."""
    import tempfile

    fd, temp_name = tempfile.mkstemp(prefix=".known_hosts.", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for line in lines:
                handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise
