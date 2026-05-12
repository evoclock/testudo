"""
Module: testudo.runtime.docker

Purpose: Docker subprocess wrapper. Provides a pure ``build_docker_argv``
function that turns a workflow path, run directory, optional inputs
directory, and an ``IsolationProfile`` into the canonical ``docker run``
argv. ``invoke`` runs the constructed argv as a subprocess and returns a
``RunResult`` with exit status, stdio, and wall-clock runtime in
milliseconds.

Inputs: paths plus an ``IsolationProfile``; optional timeout in seconds.

Outputs: a list of strings (argv) from ``build_docker_argv``; a
``RunResult`` from ``invoke``.

Assumptions: Docker is available on the host. ``invoke`` does not check
upfront; ``subprocess.run`` will raise ``FileNotFoundError`` if ``docker``
is missing, which the caller should convert into a friendlier message. The
v0.1 image (``testudo:0.1``) sets its entrypoint to the in-container
orchestrator, so callers only need to pass the workflow path as CMD.

Failure modes: subprocess timeout raises ``subprocess.TimeoutExpired``;
non-zero exit codes from the container are returned as ``RunResult.exit_status``
without raising.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from testudo.runtime.isolation import IsolationProfile


@dataclass(frozen=True, slots=True)
class RunResult:
    """Outcome of a single Docker-isolated workflow run."""

    exit_status: int
    stdout: str
    stderr: str
    runtime_ms: int


def build_docker_argv(
    *,
    workflow_path: Path,
    runs_dir: Path,
    isolation: IsolationProfile,
    inputs_dir: Path | None = None,
) -> list[str]:
    """Build the canonical ``docker run`` argv for a workflow invocation.

    The argv mounts:
      - ``workflow_path`` at ``/workflow.json`` (read-only)
      - ``inputs_dir`` (if provided) at ``/inputs`` (read-only)
      - ``runs_dir`` at ``/runs`` (read-write; the rollback/output layer)

    Resource and isolation flags come from ``isolation``: ``--cpus``,
    ``--memory``, ``--network``, ``--read-only`` plus ``--tmpfs /tmp`` when
    the root filesystem is read-only, and ``-w`` for the working directory.
    The image's ENTRYPOINT runs the orchestrator; only the workflow path is
    appended as CMD.
    """
    argv: list[str] = ["docker", "run", "--rm"]

    argv.extend(["--cpus", isolation.cpu])
    argv.extend(["--memory", isolation.memory])
    argv.extend(["--network", isolation.network])

    if isolation.read_only:
        argv.append("--read-only")
        argv.extend(["--tmpfs", "/tmp"])

    argv.extend(["-v", f"{workflow_path.resolve()}:/workflow.json:ro"])
    if inputs_dir is not None:
        argv.extend(["-v", f"{inputs_dir.resolve()}:/inputs:ro"])
    argv.extend(["-v", f"{runs_dir.resolve()}:/runs"])

    argv.extend(["-w", isolation.workdir])
    argv.append(isolation.image)
    argv.append("/workflow.json")

    return argv


def invoke(
    *,
    workflow_path: Path,
    runs_dir: Path,
    isolation: IsolationProfile,
    inputs_dir: Path | None = None,
    timeout: float | None = None,
) -> RunResult:
    """Execute a workflow inside a Docker container; return ``RunResult``.

    Wall-clock runtime is measured around the subprocess call (host-side),
    not inside the container. Non-zero container exits are returned as
    ``exit_status`` rather than raised.
    """
    argv = build_docker_argv(
        workflow_path=workflow_path,
        runs_dir=runs_dir,
        isolation=isolation,
        inputs_dir=inputs_dir,
    )

    start = time.monotonic()
    proc = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    runtime_ms = int((time.monotonic() - start) * 1000)

    return RunResult(
        exit_status=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        runtime_ms=runtime_ms,
    )
