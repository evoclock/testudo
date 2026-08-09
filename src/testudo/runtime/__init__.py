# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Testudo runtime package.

Purpose: process-isolated execution primitives. Governed runs select the
microVM backend by default; Docker remains an explicit compatibility backend
for callers that opt in. The Runner passes a workflow, isolation profile and
host-issued contract to the selected boundary and returns a ``RunResult``.

Inputs: a workflow path plus an ``IsolationProfile``; optional inputs,
lease, attestation and capability-token paths.

Outputs: a ``RunResult`` (exit status, stdio, wall-clock runtime); a
per-run audit log file written by the ``Runner``.
"""

from testudo.artifacts import ArtifactStore, EgressRejected, ExportManifest
from testudo.runtime.attestation import RuntimeAttestation, issue_attestation, write_attestation
from testudo.runtime.backend import ExecutionBackend, coerce_backend
from testudo.runtime.capability import (
    CapabilityError,
    CapabilityToken,
    SupervisorEvent,
    WorkerSupervisor,
    WorkerTerminated,
    write_token,
)
from testudo.runtime.docker import RunResult, build_docker_argv, invoke
from testudo.runtime.firecracker import (
    ApiRequest,
    FirecrackerAPI,
    FirecrackerConfig,
    FirecrackerError,
    FirecrackerHandle,
    build_api_requests,
    launch,
)
from testudo.runtime.isolation import (
    IsolationPrimitive,
    IsolationProfile,
    NetworkMode,
    load_isolation,
)
from testudo.runtime.publisher import (
    Checkpoint,
    GitBundlePublisher,
    PublicationError,
    PublicationReceipt,
)
from testudo.runtime.runner import Runner
from testudo.runtime.signing import P256Signer, SigningError, TokenSigner

__all__ = [
    "ApiRequest",
    "ArtifactStore",
    "CapabilityError",
    "CapabilityToken",
    "Checkpoint",
    "EgressRejected",
    "ExecutionBackend",
    "ExportManifest",
    "FirecrackerAPI",
    "FirecrackerConfig",
    "FirecrackerError",
    "FirecrackerHandle",
    "GitBundlePublisher",
    "IsolationPrimitive",
    "IsolationProfile",
    "NetworkMode",
    "P256Signer",
    "PublicationError",
    "PublicationReceipt",
    "RunResult",
    "Runner",
    "RuntimeAttestation",
    "SigningError",
    "SupervisorEvent",
    "TokenSigner",
    "WorkerSupervisor",
    "WorkerTerminated",
    "build_api_requests",
    "build_docker_argv",
    "coerce_backend",
    "invoke",
    "issue_attestation",
    "launch",
    "load_isolation",
    "write_attestation",
    "write_token",
]
