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
from testudo.runtime.publisher import Checkpoint, GitBundlePublisher, PublicationError, PublicationReceipt
from testudo.runtime.isolation import (
    IsolationPrimitive,
    IsolationProfile,
    NetworkMode,
    load_isolation,
)
from testudo.runtime.runner import Runner

__all__ = [
    "ArtifactStore",
    "EgressRejected",
    "ExportManifest",
    "IsolationPrimitive",
    "IsolationProfile",
    "NetworkMode",
    "RunResult",
    "Checkpoint",
    "GitBundlePublisher",
    "PublicationError",
    "PublicationReceipt",
    "Runner",
    "RuntimeAttestation",
    "ExecutionBackend",
    "CapabilityError",
    "CapabilityToken",
    "SupervisorEvent",
    "WorkerSupervisor",
    "WorkerTerminated",
    "build_docker_argv",
    "invoke",
    "issue_attestation",
    "load_isolation",
    "write_attestation",
    "write_token",
    "coerce_backend",
]
