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
from testudo.runtime.broker import BrokerError, BrokerSession, ConnectedSocket
from testudo.runtime.capability import (
    CapabilityError,
    CapabilityToken,
    SupervisorEvent,
    WorkerSupervisor,
    WorkerTerminated,
    write_token,
)
from testudo.runtime.controller import (
    HostController,
    HostControllerError,
    HostEvent,
    HostReceipt,
    HostWorkerAdapter,
    HostWorkerLauncher,
    StopHandle,
)
from testudo.runtime.docker import RunResult, build_docker_argv, invoke
from testudo.runtime.firecracker import (
    MAX_OUTPUT_BYTES,
    ApiRequest,
    FirecrackerAPI,
    FirecrackerConfig,
    FirecrackerError,
    FirecrackerHandle,
    FirecrackerOutput,
    FirecrackerVsockConnector,
    build_api_requests,
    launch,
    launch_worker,
    open_broker_session,
)
from testudo.runtime.firecracker_adapter import (
    AdapterError,
    FirecrackerAdapter,
    FirecrackerAdapterError,
    FirecrackerHostAdapter,
    FirecrackerRunPaths,
    LinuxFirecrackerAdapter,
    RunPaths,
    build_firecracker_adapter,
    create_firecracker_adapter,
)
from testudo.runtime.guest import GuestError, GuestSession
from testudo.runtime.host_runtime import GovernedRunnerConfig, build_governed_runner
from testudo.runtime.isolation import (
    IsolationPrimitive,
    IsolationProfile,
    NetworkMode,
    load_isolation,
)
from testudo.runtime.policy import NetworkPolicy, StoragePolicy, policy_digest
from testudo.runtime.publisher import (
    Checkpoint,
    GitBundlePublisher,
    PublicationError,
    PublicationReceipt,
)
from testudo.runtime.runner import (
    Runner,
    RunnerAuthorization,
    RunnerAuthorizationProvider,
    RunnerMicroVMController,
)
from testudo.runtime.signing import P256Signer, SigningError, TokenSigner
from testudo.runtime.transport import (
    MAX_FRAME_BYTES,
    Frame,
    TransportError,
    decode_frame,
    encode_frame,
    read_frame,
    write_frame,
)
from testudo.runtime.worker import ProcessHandle, VMHandle, WorkerLifecycle

__all__ = [
    "MAX_FRAME_BYTES",
    "MAX_OUTPUT_BYTES",
    "AdapterError",
    "ApiRequest",
    "ArtifactStore",
    "BrokerError",
    "BrokerSession",
    "CapabilityError",
    "CapabilityToken",
    "Checkpoint",
    "ConnectedSocket",
    "EgressRejected",
    "ExecutionBackend",
    "ExportManifest",
    "FirecrackerAPI",
    "FirecrackerAdapter",
    "FirecrackerAdapterError",
    "FirecrackerConfig",
    "FirecrackerError",
    "FirecrackerHandle",
    "FirecrackerHostAdapter",
    "FirecrackerOutput",
    "FirecrackerRunPaths",
    "FirecrackerVsockConnector",
    "Frame",
    "GitBundlePublisher",
    "GovernedRunnerConfig",
    "GuestError",
    "GuestSession",
    "HostController",
    "HostControllerError",
    "HostEvent",
    "HostReceipt",
    "HostWorkerAdapter",
    "HostWorkerLauncher",
    "IsolationPrimitive",
    "IsolationProfile",
    "LinuxFirecrackerAdapter",
    "NetworkMode",
    "NetworkPolicy",
    "P256Signer",
    "ProcessHandle",
    "PublicationError",
    "PublicationReceipt",
    "RunPaths",
    "RunResult",
    "Runner",
    "RunnerAuthorization",
    "RunnerAuthorizationProvider",
    "RunnerMicroVMController",
    "RuntimeAttestation",
    "SigningError",
    "StopHandle",
    "StoragePolicy",
    "SupervisorEvent",
    "TokenSigner",
    "TransportError",
    "VMHandle",
    "WorkerLifecycle",
    "WorkerSupervisor",
    "WorkerTerminated",
    "build_api_requests",
    "build_docker_argv",
    "build_firecracker_adapter",
    "build_governed_runner",
    "coerce_backend",
    "create_firecracker_adapter",
    "decode_frame",
    "encode_frame",
    "invoke",
    "issue_attestation",
    "launch",
    "launch_worker",
    "load_isolation",
    "open_broker_session",
    "policy_digest",
    "read_frame",
    "write_attestation",
    "write_frame",
    "write_token",
]
