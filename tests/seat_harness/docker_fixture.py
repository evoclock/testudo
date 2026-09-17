"""Disposable Linux sshd fixture for the seat-control harness.

SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later

Spec section 8 requires a disposable local SSH server standing in for the
controlled host. This module runs a real Linux sshd inside a Docker
container built **offline** from a locally present Debian 12 base image
(``public ``debian:12`` base (pulled on first use; openssh-server installed at build time).

Lifecycle (all disposable, per session):

1. ``build_image()``   — ``docker build`` from ``docker/Dockerfile`` (public
   ``debian:12`` base; the pull happens on first use, apt runs at build
   time, and the result is cached for the session).
2. ``start()``         — create a container on a dedicated bridge network
   (``testudo-seat-harness``), inject the fixture user's authorized key,
   start sshd as PID 1 in the foreground, wait for the TCP port.
3. ``run()``           — ``docker exec`` for one-shot provisioning commands.
4. ``stop()``          — remove the container, the dedicated network, and
   the built image so nothing survives the test session.

If Docker is unavailable or the image cannot be built (for example a CI
runner without network access), the harness skips with an explicit reason
instead of erroring. The fallback is a **native macOS sshd**
(``tests/seat_harness/native_sshd.py``) so the suite still runs offline on
this dev machine; Linux CI uses the container. Every test that depends on
Linux semantics (flock, setsid, /proc, GNU stat/timeout) is gated on
``FixtureHost.is_linux`` and documents the mock boundary, as section 8
requires.
"""

from __future__ import annotations

import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

DOCKER_IMAGE = "testudo-seat-harness:sshd-fixture"
DOCKER_NETWORK = "testudo-seat-harness"
CONTAINER_PREFIX = "testudo-seat-harness"
BASE_IMAGE = "debian:12"  # public Docker Hub base; pullable in CI

CONTAINER_SSH_PORT = 22


class DockerFixtureError(RuntimeError):
    """Raised when the disposable Docker fixture cannot reach a lifecycle step."""


@dataclass
class DockerFixture:
    """A disposable Linux sshd container standing in for the controlled host."""

    container_name: str
    port: int  # published 127.0.0.1 port on the host
    username: str = "fixture"

    # -- low-level docker invocation ------------------------------------

    @staticmethod
    def _docker(
        *args: str, check: bool = True, timeout: int = 120
    ) -> subprocess.CompletedProcess[str]:
        proc = subprocess.run(
            ["docker", *args],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        if check and proc.returncode != 0:
            raise DockerFixtureError(
                f"docker {' '.join(args)} failed rc={proc.returncode}: {proc.stderr.strip()[:2000]}"
            )
        return proc

    # -- lifecycle -------------------------------------------------------

    @staticmethod
    def docker_available() -> bool:
        return shutil.which("docker") is not None

    @classmethod
    def build_image(cls, dockerfile_dir: Path) -> None:
        """Build the fixture image from the public debian:12 base.

        Raises ``DockerFixtureError`` when the build fails (missing base,
        no network for apt, daemon down); the session fixture turns that
        into an explicit skip so a default CI job never hard-fails.
        """
        cls._docker(
            "build",
            "-q",
            "-t",
            DOCKER_IMAGE,
            str(dockerfile_dir),
        )

    @classmethod
    def create(
        cls,
        dockerfile_dir: Path,
        pubkey: str,
        *,
        host_port: int | None = None,
    ) -> DockerFixture:
        """Create, start, and provision one disposable fixture container."""
        if not cls.docker_available():
            raise DockerFixtureError("docker is not available on this host")
        cls.build_image(dockerfile_dir)
        cls._docker("network", "create", DOCKER_NETWORK, check=False)

        container = f"{CONTAINER_PREFIX}-{secrets.token_hex(4)}"
        publish = ["-p", f"127.0.0.1:{host_port}:22"] if host_port else ["-p", "127.0.0.1::22"]
        cls._docker(
            "run",
            "-d",
            "--name",
            container,
            "--network",
            DOCKER_NETWORK,
            "--cpus",
            "2",
            "--memory",
            "1g",
            "--entrypoint",
            "/usr/sbin/sshd",  # the base image's default entrypoint validates argv modes
            *publish,
            DOCKER_IMAGE,
            "-D",
            "-e",
        )

        fixture = cls(container_name=container, port=0)
        fixture.port = int(
            cls._docker("port", container, "22/tcp")
            .stdout.strip()
            .splitlines()[0]
            .rsplit(":", 1)[1]
        )

        # Provision: install the authorized key, wait for sshd readiness.
        fixture._provision(pubkey)
        return fixture

    def _provision(self, pubkey: str) -> None:
        deadline = time.monotonic() + 60
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                self.run_as_fixture(
                    f"mkdir -p -m 700 ~/.ssh && printf '%s\\n' {_shell_quote(pubkey)} > ~/.ssh/authorized_keys"
                )
                self.run("sshd -t")  # config sanity from root
                return
            except DockerFixtureError as exc:  # container still starting
                last_error = exc
                time.sleep(0.5)
        raise DockerFixtureError(f"fixture container never became ready: {last_error}")

    def run(self, command: str, *, timeout: float = 60) -> str:
        """Run a one-shot shell command inside the container.

        Runs as root by default; pass ``user`` for the fixture account (the
        fixture user's ``~/.ssh`` must be owned by them for sshd StrictModes).
        """
        return self._run_as(command, user=None, timeout=timeout)

    def run_as_fixture(self, command: str, *, timeout: float = 60) -> str:
        """Run a one-shot shell command as the fixture user."""
        return self._run_as(command, user=self.username, timeout=timeout)

    def _run_as(self, command: str, *, user: str | None, timeout: float) -> str:
        args = ["exec"]
        if user:
            args += ["-u", user]
        args += [self.container_name, "/bin/sh", "-c", command]
        proc = self._docker(*args, timeout=int(timeout) + 30)
        if proc.returncode != 0:
            raise DockerFixtureError(
                f"container command failed rc={proc.returncode}: {proc.stderr.strip()[:2000]}"
            )
        return proc.stdout

    def stop(self) -> None:
        """Remove the container, its dedicated network, and the built image.

        Everything the fixture created is gone after the session: container,
        bridge network, and image (the README's "everything is removed").
        """
        self._docker("rm", "-f", self.container_name, check=False)
        self._docker("network", "rm", DOCKER_NETWORK, check=False)
        self._docker("image", "rm", DOCKER_IMAGE, check=False)

    @classmethod
    def cleanup_stale(cls) -> None:
        """Remove leftover fixture containers/network from a crashed session."""
        proc = cls._docker(
            "ps",
            "-a",
            "--format",
            "{{.Names}}",
            "--filter",
            f"name={CONTAINER_PREFIX}-",
            check=False,
        )
        for name in proc.stdout.split():
            cls._docker("rm", "-f", name, check=False)
        cls._docker("network", "rm", DOCKER_NETWORK, check=False)


def _shell_quote(value: str) -> str:
    import shlex

    return shlex.quote(value)
