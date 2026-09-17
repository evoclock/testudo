"""Shared fixtures for the seat-control harness (spec section 8).

SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from .docker_fixture import DockerFixture, DockerFixtureError
from .guard_client import SshRunner
from .native_sshd import NativeSshd, NativeSshdError
from .normative import assert_pins_match, extract_normative_scripts
from .shims import LOGINCTL_SHIM, SHIM_DIR, SYSTEMCTL_SHIM

HARNESS_DIR = Path(__file__).resolve().parent
DOCKER_DIR = HARNESS_DIR / "docker"


@dataclass
class FixtureHost:
    """One disposable SSH-reachable host standing in for the controlled seat host.

    Both backends populate every field (no dynamic attributes), so tests can
    read ``keys_dir``/``destination``/``port`` uniformly and platform-gated
    tests skip cleanly instead of erroring on a missing attribute.
    """

    destination: str  # ssh destination: user@host (docker) or localhost (native)
    port: int
    keys_dir: Path  # session dir holding userkey, userkey.pub, known_hosts
    backend: str  # "docker" | "native-macos"
    is_linux: bool
    docker_fixture: DockerFixture | None = None
    native: NativeSshd | None = None

    @property
    def linux_semantics(self) -> bool:
        """True when the remote end has Linux /proc, setsid, flock, GNU stat."""
        return self.is_linux


class SshSession:
    """Thin persistent-control channel to the fixture host (docker exec or ssh)."""

    def __init__(self, host: FixtureHost) -> None:
        self._host = host

    def run(self, command: str, *, timeout: float = 60) -> subprocess.CompletedProcess[str]:
        if self._host.docker_fixture is not None:
            # Run as the fixture user: ~ must resolve to /home/fixture so that
            # paths like ~/.testudo and ~/.fixture-state match the SSH view.
            fixture = self._host.docker_fixture
            return fixture._docker(
                "exec",
                "-u",
                fixture.username,
                fixture.container_name,
                "/bin/sh",
                "-c",
                command,
                check=False,
            )
        assert self._host.native is not None
        return subprocess.run(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-i",
                str(self._host.native.user_key_path),
                "-p",
                str(self._host.native.port),
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "localhost",
                command,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def run_as_root(self, command: str, *, timeout: float = 60) -> subprocess.CompletedProcess[str]:
        """Root-level control channel (docker exec as root; docker backend only)."""
        fixture = self._host.docker_fixture
        assert fixture is not None, "run_as_root requires the Docker fixture"
        return fixture._docker(
            "exec",
            fixture.container_name,
            "/bin/sh",
            "-c",
            command,
            check=False,
        )


@pytest.fixture(scope="session")
def seat_fixture_host(tmp_path_factory: pytest.TempPathFactory) -> Iterator[FixtureHost]:
    """One disposable SSH host per pytest session.

    Prefers the Linux Docker fixture (full Template C semantics: /proc,
    setsid, flock, GNU stat/timeout). If Docker is present but the fixture
    cannot be built or started, the harness skips with an explicit reason
    (a default CI ``pytest -ra`` job must not hard-fail). Without Docker it
    falls back to a native macOS sshd, where Linux-only tests gate
    themselves via ``fixture_host.linux_semantics`` and skip cleanly.
    """
    if DockerFixture.docker_available():
        DockerFixture.cleanup_stale()
        keys = tmp_path_factory.mktemp("seat-harness-keys")
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(keys / "userkey")],
            check=True,
            capture_output=True,
        )
        pubkey = (keys / "userkey.pub").read_text().strip()
        try:
            fixture = DockerFixture.create(DOCKER_DIR, pubkey)
        except DockerFixtureError as exc:
            pytest.skip(
                "seat harness: the Docker fixture could not be built or started "
                f"({exc}); skipping the Docker-backed harness tests"
            )
        try:
            yield FixtureHost(
                destination=f"{fixture.username}@127.0.0.1",
                port=fixture.port,
                keys_dir=keys,
                backend="docker",
                is_linux=True,
                docker_fixture=fixture,
            )
        finally:
            fixture.stop()
        return

    if not NativeSshd.available():
        pytest.skip(
            "seat harness: neither a usable Docker daemon nor a native "
            "/usr/sbin/sshd is available on this host; skipping the harness"
        )
    state = tmp_path_factory.mktemp("native-sshd")
    native = NativeSshd(state)
    try:
        native.start()
    except NativeSshdError as exc:
        pytest.skip(f"seat harness: native sshd fixture failed to start ({exc})")
    try:
        yield FixtureHost(
            destination="localhost",
            port=native.port,
            keys_dir=state,
            backend="native-macos",
            is_linux=False,
            native=native,
        )
    finally:
        native.stop()


@pytest.fixture
def ssh_session(seat_fixture_host: FixtureHost) -> SshSession:
    return SshSession(seat_fixture_host)


@pytest.fixture
def install_shims(seat_fixture_host: FixtureHost, ssh_session: SshSession) -> Iterator[None]:
    """Upload the systemctl/loginctl shims into the fixture PATH and clean up.

    The shim directory (/opt/testudo-fixture/bin) is provisioned by the
    Docker image and placed first on PATH by the fixture login shell; the
    native macOS backend has no equivalent user-writable login-PATH slot,
    so shim-dependent tests skip there with this explicit reason.
    """
    if seat_fixture_host.backend != "docker":
        pytest.skip(
            "fixture systemctl/loginctl shims are provisioned only in the "
            "Docker fixture (login-shell PATH injection); skipping on the "
            "native backend"
        )
    ssh_session.run(f"mkdir -p -m 755 {SHIM_DIR} ~/.fixture-state")
    _upload(ssh_session, f"{SHIM_DIR}/systemctl", SYSTEMCTL_SHIM)
    _upload(ssh_session, f"{SHIM_DIR}/loginctl", LOGINCTL_SHIM)
    yield
    ssh_session.run(f"rm -f {SHIM_DIR}/systemctl {SHIM_DIR}/loginctl")


def _upload(session: SshSession, remote_path: str, content: str) -> None:
    hex_payload = content.encode().hex()
    # Keep the command short: pipe the hex through python3 (present in both
    # fixture backends) to decode; avoids relying on xxd.
    script = (
        f"python3 -c \"import sys; sys.stdout.buffer.write(bytes.fromhex('{hex_payload}'))\" "
        f"> {remote_path} && chmod 755 {remote_path}"
    )
    proc = session.run(script, timeout=30)
    if proc.returncode != 0:
        raise AssertionError(f"shim upload failed: {proc.stderr}")


@pytest.fixture(scope="session")
def normative_scripts() -> dict[str, str]:
    """Byte-exact normative scripts from the spec, digests pinned."""
    drifted = assert_pins_match()
    assert drifted is None, f"normative script digests drifted from pins: {drifted}"
    return extract_normative_scripts()


@dataclass
class GuardEnv:
    """Per-test helper bundle for driving guarded operations over SSH."""

    host: FixtureHost

    @property
    def key_path(self) -> Path:
        return self.host.keys_dir / "userkey"

    @property
    def destination(self) -> str:
        return self.host.destination

    @property
    def port(self) -> int:
        return self.host.port

    def ssh_runner(self) -> SshRunner:
        known = self.host.keys_dir / "known_hosts"
        if not known.exists():
            known.write_text("")
        return SshRunner(self.host.destination, self.key_path, self.host.port, known)

    def session(self) -> SshSession:
        return SshSession(self.host)


@pytest.fixture
def guard_env(seat_fixture_host: FixtureHost) -> GuardEnv:
    """Per-test guard environment: key path, destination, and helper factory."""
    return GuardEnv(seat_fixture_host)
