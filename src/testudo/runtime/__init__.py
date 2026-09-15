# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Testudo runtime package.

Purpose: process-isolated execution primitives. Governed runs select the
microVM backend by default, with native containers as the explicit macOS
boundary. Docker remains an explicit compatibility backend and never acts as a
fallback. The Runner passes a workflow, isolation profile and
host-issued contract to the selected boundary and returns a ``RunResult``.

Inputs: a workflow path plus an ``IsolationProfile``; optional inputs,
lease, attestation and capability-token paths.

Outputs: a ``RunResult`` (exit status, stdio, wall-clock runtime); a
per-run audit log file written by the ``Runner``.
"""

from testudo.artifacts import ArtifactStore, EgressRejected, ExportManifest
from testudo.runtime.assignment import (
    AssignmentError,
    AssignmentEvent,
    AssignmentReceipt,
    AssignmentRequest,
    AssignmentService,
    DispatcherVerifier,
    PiJourney,
)
from testudo.runtime.assignment_protocol import (
    CommandSessionVerifier,
    SessionSecret,
    command_credential,
    handle_command,
    provision_session_secret,
    serve_framed,
)
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
from testudo.runtime.host_runtime import (
    GovernedNativeContainerRunnerConfig,
    GovernedRunnerConfig,
    build_governed_runner,
)
from testudo.runtime.isolation import (
    IsolationPrimitive,
    IsolationProfile,
    NetworkMode,
    RootfsFormat,
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
    RunnerController,
    RunnerMicroVMController,
    RunnerResult,
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
    "AssignmentError",
    "AssignmentEvent",
    "AssignmentReceipt",
    "AssignmentRequest",
    "AssignmentService",
    "BrokerError",
    "BrokerSession",
    "CapabilityError",
    "CapabilityToken",
    "Checkpoint",
    "CommandSessionVerifier",
    "ConnectedSocket",
    "DispatcherVerifier",
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
    "GovernedNativeContainerRunnerConfig",
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
    "PiJourney",
    "ProcessHandle",
    "PublicationError",
    "PublicationReceipt",
    "RootfsFormat",
    "RunPaths",
    "RunResult",
    "Runner",
    "RunnerAuthorization",
    "RunnerAuthorizationProvider",
    "RunnerController",
    "RunnerMicroVMController",
    "RunnerResult",
    "RuntimeAttestation",
    "SessionSecret",
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
    "command_credential",
    "create_firecracker_adapter",
    "decode_frame",
    "encode_frame",
    "handle_command",
    "invoke",
    "issue_attestation",
    "launch",
    "launch_worker",
    "load_isolation",
    "open_broker_session",
    "policy_digest",
    "provision_session_secret",
    "read_frame",
    "serve_framed",
    "write_attestation",
    "write_frame",
    "write_token",
]
