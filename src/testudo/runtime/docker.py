# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Host-side Docker invocation with read-only contained-work inputs."""

from __future__ import annotations

import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from testudo.runtime.isolation import IsolationProfile

_AUTH_ENV_NAMES = frozenset(
    {
        "CANTUS_APPROVAL_HASH",
        "CANTUS_APPROVAL_REF",
        "CANTUS_TASK_HASH",
        "CANTUS_TICKET_HASH",
        "CANTUS_SPEC_HASH",
        "CANTUS_DOD_HASH",
        "CANTUS_WORK_STARTED_AT",
        "CANTUS_RUNTIME_ATTESTATION_HASH",
    }
)


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
    lease_path: Path | None = None,
    attestation_path: Path | None = None,
    capability_token_path: Path | None = None,
    authorization_env: Mapping[str, str] | None = None,
) -> list[str]:
    """Build ``docker run`` argv with no writable host control mounts.

    ``runs_dir`` is the only writable mount. If a lease is supplied, the lease,
    short-lived runtime attestation and host-issued capability token are mounted
    read-only under ``/run/testudo`` and the unattended flag is injected by the
    host. Arbitrary environment variables are rejected in contained mode.
    """
    contained = (
        lease_path is not None
        or attestation_path is not None
        or capability_token_path is not None
        or authorization_env is not None
    )
    if contained and (lease_path is None or attestation_path is None or capability_token_path is None):
        raise ValueError("lease_path, attestation_path, and capability_token_path are required together")
    if contained and authorization_env is None:
        raise ValueError("authorization_env is required for contained mode")
    if not contained and authorization_env:
        raise ValueError("authorization_env requires a lease and attestation")
    if lease_path is not None and not lease_path.is_file():
        raise ValueError(f"lease file does not exist: {lease_path}")
    if attestation_path is not None and not attestation_path.is_file():
        raise ValueError(f"attestation file does not exist: {attestation_path}")
    if capability_token_path is not None and not capability_token_path.is_file():
        raise ValueError(f"capability token file does not exist: {capability_token_path}")
    if authorization_env is not None and set(authorization_env) - _AUTH_ENV_NAMES:
        unknown = sorted(set(authorization_env) - _AUTH_ENV_NAMES)
        raise ValueError(f"unsupported authorization environment: {', '.join(unknown)}")

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

    if contained:
        assert (
            lease_path is not None
            and attestation_path is not None
            and capability_token_path is not None
            and authorization_env is not None
        )
        argv.extend(["-v", f"{lease_path.resolve()}:/run/testudo/lease.json:ro"])
        argv.extend(["-v", f"{attestation_path.resolve()}:/run/testudo/attestation.json:ro"])
        argv.extend(["-v", f"{capability_token_path.resolve()}:/run/testudo/capability-token.json:ro"])
        argv.extend(["--env", "CANTUS_UNATTENDED=1"])
        argv.extend(["--env", "CANTUS_LEASE_FILE=/run/testudo/lease.json"])
        argv.extend(["--env", "CANTUS_RUNTIME_ATTESTATION_FILE=/run/testudo/attestation.json"])
        argv.extend(["--env", "TESTUDO_CAPABILITY_TOKEN_FILE=/run/testudo/capability-token.json"])
        for key in sorted(authorization_env):
            argv.extend(["--env", f"{key}={authorization_env[key]}"])

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
    lease_path: Path | None = None,
    attestation_path: Path | None = None,
    capability_token_path: Path | None = None,
    authorization_env: Mapping[str, str] | None = None,
) -> RunResult:
    """Execute a workflow inside Docker and return its host-observed result."""
    argv = build_docker_argv(
        workflow_path=workflow_path,
        runs_dir=runs_dir,
        isolation=isolation,
        inputs_dir=inputs_dir,
        lease_path=lease_path,
        attestation_path=attestation_path,
        capability_token_path=capability_token_path,
        authorization_env=authorization_env,
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
