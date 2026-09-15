# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Governed Linux/Spark Firecracker adapter.

The lower-level :mod:`testudo.runtime.firecracker` module deliberately stops at
process, API and vsock primitives.  This module is the host-controller seam
which composes those primitives with the Runner contract.  It admits one
networkless, read-only microVM at a time, reads the workflow and input maps on
the host, and sends those maps over the already-connected broker.  No host
workflow, input directory, repository, credential, or artifact directory is
mounted into the guest.

All process, broker and token operations are injectable.  The default path is
therefore usable on a Linux/KVM host while tests can exercise the complete
admission and cleanup state machine without KVM, a listener, a socket, or a
real Firecracker binary.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from re import fullmatch
from typing import Any, Protocol, cast

from testudo.runtime.broker import BrokerSession
from testudo.runtime.capability import CapabilityError, CapabilityToken
from testudo.runtime.containment import containment_contract
from testudo.runtime.controller import (
    HostController,
    HostEvent,
    HostWorkerAdapter,
    StopHandle,
)
from testudo.runtime.docker import RunResult
from testudo.runtime.firecracker import (
    FirecrackerConfig,
    FirecrackerError,
    FirecrackerOutput,
    FirecrackerVsockConnector,
    launch_worker,
    open_broker_session,
)
from testudo.runtime.isolation import IsolationProfile
from testudo.runtime.runner import RunnerMicroVMController
from testudo.runtime.signing import TokenSigner
from testudo.runtime.worker import WorkerLifecycle

_SHA256 = r"[0-9a-f]{64}"
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
_TOKEN_IDENTITY_FIELDS = (
    "run_id",
    "lease_id",
    "host_id",
    "vm_id",
    "repository",
    "branch",
    "base_sha",
)


class FirecrackerAdapterError(RuntimeError):
    """A governed Firecracker run cannot be admitted or completed."""


# A shorter name is convenient for callers and keeps failures easy to catch.
AdapterError = FirecrackerAdapterError


class _BrokerLike(Protocol):
    @property
    def state(self) -> str:
        """Return the broker state."""

    def bootstrap(self, contract: Mapping[str, object]) -> object:
        """Bootstrap the guest, or return the already-completed handshake."""

    def run(self, workflow: Mapping[str, Any], inputs: Mapping[str, Any]) -> object:
        """Send one workflow map and one input map."""

    def receive(self) -> object:
        """Receive one guest frame."""

    def stop(self, reason: str = "operator_stop") -> object:
        """Request a guest stop."""

    def close(self) -> None:
        """Close the broker."""


class _WorkerLauncher(Protocol):
    def __call__(
        self, config: FirecrackerConfig, token: CapabilityToken, **kwargs: object
    ) -> WorkerLifecycle:
        """Launch one already-admitted worker."""


class _BrokerOpener(Protocol):
    def __call__(self, config: FirecrackerConfig, **kwargs: object) -> BrokerSession:
        """Open one broker session."""


class _TokenLoader(Protocol):
    def __call__(self, value: object) -> CapabilityToken | Mapping[str, Any]:
        """Load or verify one capability token."""


@dataclass(frozen=True, slots=True)
class FirecrackerRunPaths:
    """Transient host paths owned by one adapter run.

    ``exchange_dir`` is intentionally retained for Runner's egress importer;
    only the API/vsock endpoints are transient adapter state.
    """

    run_dir: Path
    exchange_dir: Path
    api_socket: Path
    vsock_socket: Path


# A descriptive alias used by integrations that call this object ``RunPaths``.
RunPaths = FirecrackerRunPaths


@dataclass(frozen=True, slots=True)
class _PreparedRun:
    run_id: str
    workflow_name: str
    isolation: IsolationProfile
    paths: FirecrackerRunPaths
    config: FirecrackerConfig
    token: CapabilityToken
    contract: Mapping[str, object]
    guest_port: int


class _BrokerProxy:
    """Make ``open_broker_session`` compatible with HostController.

    ``open_broker_session`` completes the guest ready handshake by design,
    while ``HostController`` owns that handshake for an injected adapter.  The
    proxy turns the second controller bootstrap into a no-op when the lower
    layer already reached ``ready`` and delegates all other operations.
    """

    def __init__(self, session: _BrokerLike, *, run_id: str, token_id: str, nonce: str) -> None:
        self._session = session
        self._run_id = run_id
        self._token_id = token_id
        self._nonce = nonce
        self._bootstrapped = getattr(session, "state", "new") == "ready"
        self._closed = False

    @property
    def state(self) -> str:
        return cast(str, getattr(self._session, "state", "ready" if self._bootstrapped else "new"))

    def bootstrap(self, contract: Mapping[str, object]) -> object:
        if self._bootstrapped:
            # HostController does not inspect this frame; the shape mirrors the
            # actual ready frame and avoids fabricating any guest output.
            from testudo.runtime.transport import Frame

            return Frame(
                sequence=0,
                run_id=self._run_id,
                token_id=self._token_id,
                nonce=self._nonce,
                kind="ready",
                payload={"protocol": "testudo.vsock.frame.v1"},
            )
        result = self._session.bootstrap(contract)
        self._bootstrapped = True
        return result

    def run(self, workflow: Mapping[str, Any], inputs: Mapping[str, Any]) -> object:
        return self._session.run(workflow, inputs)

    def receive(self) -> object:
        return self._session.receive()

    def stop(self, reason: str = "operator_stop") -> object:
        return self._session.stop(reason)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._session.close()


class _AdapterBinding:
    """HostController's worker binding around a lifecycle and broker."""

    def __init__(self, lifecycle: WorkerLifecycle, broker: _BrokerLike) -> None:
        self.lifecycle = lifecycle
        self.broker = cast(BrokerSession, broker)
        self._closed = False

    def collect_output(self, *, timeout: float | None = 5.0) -> FirecrackerOutput:
        handle = getattr(self.lifecycle, "handle", None)
        collector = getattr(handle, "collect_output", None)
        if callable(collector):
            output = collector(timeout=timeout)
            if isinstance(output, FirecrackerOutput):
                return output
        return FirecrackerOutput("", "")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.broker.close()
        # HostController normally stops a binding before close on every error
        # path.  The fallback makes direct adapter cleanup safe as well.
        if not getattr(self.lifecycle, "closed", True):
            with suppress(BaseException):
                self.lifecycle.stop("adapter_close")


class _RunCleanup:
    """Idempotent token revocation and transient-path wipe for one run."""

    def __init__(
        self,
        token_id: str,
        paths: FirecrackerRunPaths,
        revoke: Callable[[str], None],
        wipe: Callable[[], None],
    ) -> None:
        self.token_id = token_id
        self.paths = paths
        self._revoke_external = revoke
        self._wipe_external = wipe
        self._lock = threading.Lock()
        self._revoked = False
        self._wiped = False

    @property
    def revoked(self) -> bool:
        return self._revoked

    @property
    def wiped(self) -> bool:
        return self._wiped

    def revoke(self, token_id: str | None = None) -> None:
        expected = self.token_id if token_id is None else token_id
        if expected != self.token_id:
            raise FirecrackerAdapterError("token revocation identity mismatch")
        with self._lock:
            if self._revoked:
                return
            self._revoked = True
        self._revoke_external(self.token_id)

    def wipe(self) -> None:
        with self._lock:
            if self._wiped:
                return
            self._wiped = True
        try:
            self._wipe_external()
        finally:
            # FirecrackerHandle also owns this cleanup.  The paths are removed
            # here for constructor/open-session failures where no handle exists.
            for path in (self.paths.api_socket, self.paths.vsock_socket):
                with suppress(FileNotFoundError, OSError):
                    if path.exists() and (path.is_socket() or path.is_file()):
                        path.unlink()

    def cleanup_without_worker(self) -> None:
        """Attempt revocation and wipe independently, preserving both calls."""
        failures: list[BaseException] = []
        for operation in (self.revoke, self.wipe):
            try:
                operation()
            except BaseException as exc:
                failures.append(exc)
        if failures:
            primary = failures[0]
            for failure in failures[1:]:
                primary.add_note(
                    f"additional adapter cleanup failed: {type(failure).__name__}: {failure}"
                )
            raise primary


class FirecrackerAdapter(RunnerMicroVMController):
    """Concrete governed Firecracker implementation of Runner's microVM seam.

    The adapter is intentionally one-shot: a new instance may execute many
    sequential runs, but only one run can be active at a time.  A capability
    token, lease and attestation are required for every run.  The token is
    verified before launching Firecracker and its complete identity is copied
    into the guest bootstrap contract.
    """

    def __init__(
        self,
        binary: Path | str | None = None,
        *,
        firecracker_binary: Path | str | None = None,
        runs_root: Path | str | None = None,
        host_id: str | None = None,
        repository: str | None = None,
        branch: str | None = None,
        base_sha: str | None = None,
        signing_key: bytes | None = None,
        signer: TokenSigner | None = None,
        revoke_token: Callable[[str], None] | None = None,
        wipe_vm: Callable[[], None] | None = None,
        artifact_digest: str | None = None,
        token_loader: _TokenLoader | None = None,
        worker_launcher: _WorkerLauncher | None = None,
        launcher: _WorkerLauncher | None = None,
        broker_opener: _BrokerOpener | None = None,
        open_session: _BrokerOpener | None = None,
        connector_factory: Callable[[FirecrackerConfig, int], FirecrackerVsockConnector]
        | None = None,
        socket_factory: Callable[..., object] | None = None,
        popen: Callable[..., object] | None = None,
        startup_timeout: float = 5.0,
        boot_args: str = "console=ttyS0 reboot=k panic=1 pci=off",
        vcpu_count: int | None = None,
        mem_size_mib: int | None = None,
        now: Callable[[], datetime] | None = None,
        clock: Callable[[], float] = time.monotonic,
        controller_factory: Callable[..., HostController] | None = None,
        validate_socket_paths: bool | None = None,
    ) -> None:
        selected_binary = binary if binary is not None else firecracker_binary
        if selected_binary is None:
            raise ValueError("a Firecracker binary path is required")
        if (
            binary is not None
            and firecracker_binary is not None
            and Path(binary) != Path(firecracker_binary)
        ):
            raise ValueError("binary and firecracker_binary must match")
        if startup_timeout <= 0:
            raise ValueError("startup_timeout must be positive")
        if vcpu_count is not None and vcpu_count < 1:
            raise ValueError("vcpu_count must be positive")
        if mem_size_mib is not None and mem_size_mib < 128:
            raise ValueError("mem_size_mib is below the safe minimum")
        if artifact_digest is not None:
            _require_artifact_digest(artifact_digest)
        self.binary = Path(selected_binary)
        self.runs_root = None if runs_root is None else Path(runs_root)
        self.host_id = host_id
        self.repository = repository
        self.branch = branch
        self.base_sha = base_sha
        self.signing_key = signing_key
        self.signer = signer
        self._revoke_external = revoke_token
        self._wipe_external = wipe_vm
        self.artifact_digest = artifact_digest
        self._token_loader = token_loader
        self._worker_launcher = worker_launcher or launcher or cast(_WorkerLauncher, launch_worker)
        self._broker_opener = (
            broker_opener or open_session or cast(_BrokerOpener, open_broker_session)
        )
        self._connector_factory = connector_factory
        self._socket_factory = socket_factory
        self._popen = popen
        self.startup_timeout = startup_timeout
        self.boot_args = boot_args
        self.vcpu_count = vcpu_count
        self.mem_size_mib = mem_size_mib
        self._now = now
        self._clock = clock
        self._controller_factory = controller_factory
        # Injected process/broker fakes frequently run under pytest's long
        # temporary prefixes, which cannot fit Linux's AF_UNIX limit.  The
        # production default path remains strict; callers can also force the
        # check explicitly when using a custom launcher.
        self.validate_socket_paths = (
            validate_socket_paths
            if validate_socket_paths is not None
            else worker_launcher is None
            and launcher is None
            and broker_opener is None
            and open_session is None
        )
        self._active_controller: HostController | None = None
        self._active_state: _RunCleanup | None = None
        self._active_lock = threading.Lock()

    @property
    def stop_handle(self) -> StopHandle | None:
        """Return the active governed stop handle, if a run is in progress."""
        controller = self._active_controller
        return None if controller is None else controller.stop_handle

    @property
    def active_run_id(self) -> str | None:
        """Return the currently active run identity for observability/tests."""
        controller = self._active_controller
        handle = controller.stop_handle if controller is not None else None
        return None if handle is None else handle.run_id

    def run(
        self,
        *,
        run_id: str,
        workflow_path: Path,
        workflow_name: str,
        runs_dir: Path,
        isolation: IsolationProfile,
        inputs_dir: Path | None,
        timeout: float | None,
        lease_path: Path | None,
        lease_id: str | None,
        attestation_path: Path | None,
        capability_token_path: Path | None,
        authorization_env: Mapping[str, str] | None,
        image_digest: str | None,
        event_sink: Callable[[HostEvent], None],
    ) -> RunResult:
        """Admit and execute one workflow through HostController."""
        self._begin_run(run_id)
        cleanup: _RunCleanup | None = None
        try:
            prepared, workflow, inputs, cleanup = self._prepare_run(
                run_id=run_id,
                workflow_path=workflow_path,
                workflow_name=workflow_name,
                runs_dir=runs_dir,
                isolation=isolation,
                inputs_dir=inputs_dir,
                lease_path=lease_path,
                lease_id=lease_id,
                attestation_path=attestation_path,
                capability_token_path=capability_token_path,
                authorization_env=authorization_env,
                image_digest=image_digest,
            )
            self._active_state = cleanup

            def launcher(**kwargs: object) -> HostWorkerAdapter:
                return self._launch_binding(prepared, cleanup, **kwargs)

            if self._controller_factory is None:
                controller = HostController(launcher, event_sink=event_sink, clock=self._clock)
            else:
                controller = cast(
                    HostController,
                    _call_compatible(
                        self._controller_factory,
                        launcher,
                        event_sink=event_sink,
                        clock=self._clock,
                    ),
                )
            self._active_controller = controller
            result = controller.run(
                run_id=run_id,
                token_id=prepared.token.token_id,
                nonce=prepared.token.nonce,
                workflow=workflow,
                inputs=inputs,
                contract=prepared.contract,
                timeout=timeout,
            )
            # A correctly implemented WorkerLifecycle performs these actions
            # in wait().  The idempotent wrappers cover injected fakes too.
            cleanup.revoke()
            cleanup.wipe()
            return result
        except BaseException as exc:
            if cleanup is not None and not cleanup.revoked:
                _best_effort_cleanup(exc, cleanup.cleanup_without_worker)
            raise
        finally:
            self._active_controller = None
            self._active_state = None
            self._end_run()

    def _begin_run(self, run_id: str) -> None:
        if not isinstance(run_id, str) or not run_id:
            raise FirecrackerAdapterError("run_id is required")
        with self._active_lock:
            if self._active_controller is not None or self._active_state is not None:
                raise FirecrackerAdapterError("a Firecracker adapter run is already active")
            # A tiny sentinel prevents concurrent calls from both passing the
            # check before either has admitted its token.
            self._active_state = cast(_RunCleanup, _ACTIVE_SENTINEL)

    def _end_run(self) -> None:
        with self._active_lock:
            self._active_state = None

    def _prepare_run(
        self,
        *,
        run_id: str,
        workflow_path: Path,
        workflow_name: str,
        runs_dir: Path,
        isolation: IsolationProfile,
        inputs_dir: Path | None,
        lease_path: Path | None,
        lease_id: str | None,
        attestation_path: Path | None,
        capability_token_path: Path | None,
        authorization_env: Mapping[str, str] | None,
        image_digest: str | None,
    ) -> tuple[_PreparedRun, Mapping[str, Any], Mapping[str, Any], _RunCleanup]:
        if not isinstance(workflow_name, str) or not workflow_name:
            raise FirecrackerAdapterError("workflow_name is required")
        self._validate_microvm_profile(isolation)
        _require_digest(image_digest, field="image_digest")
        if not isinstance(lease_id, str) or not lease_id:
            raise FirecrackerAdapterError("contained microVM runs require lease_id")
        if lease_path is None or attestation_path is None or capability_token_path is None:
            raise FirecrackerAdapterError(
                "contained microVM runs require lease, attestation, and capability-token paths"
            )
        if authorization_env is None:
            raise FirecrackerAdapterError("contained microVM runs require authorization_env")
        if not isinstance(authorization_env, Mapping):
            raise FirecrackerAdapterError("authorization_env must be a map")
        unknown_env = sorted(set(authorization_env) - _AUTH_ENV_NAMES)
        if unknown_env:
            raise FirecrackerAdapterError(
                "unsupported authorization environment: " + ", ".join(unknown_env)
            )
        workflow = _read_json_map(workflow_path, "workflow")
        inputs = _read_inputs(inputs_dir)
        paths = self._prepare_paths(runs_dir)
        config = self._build_config(isolation, paths)
        # FirecrackerConfig validates the admitted files and the exact socket
        # boundary before the token is accepted or a process can start.
        try:
            self._validate_config(config)
        except FirecrackerError as exc:
            raise FirecrackerAdapterError(str(exc)) from exc
        token = self._load_token(capability_token_path)
        self._validate_token_binding(token, run_id=run_id, lease_id=lease_id)
        lease_data = _read_optional_map(lease_path, "lease")
        attestation_data = _read_optional_map(attestation_path, "attestation")
        self._validate_lease(lease_data, token)
        self._validate_attestation(
            attestation_data,
            token=token,
            run_id=run_id,
            image_digest=cast(str, image_digest),
            exchange_dir=paths.exchange_dir,
        )
        artifact = self._artifact_digest(isolation, cast(str, image_digest))
        contract = self._contract(
            token=token,
            run_id=run_id,
            workflow_name=workflow_name,
            isolation=isolation,
            paths=paths,
            image_digest=cast(str, image_digest),
            artifact_digest=artifact,
            attestation=attestation_data,
            authorization_env=authorization_env,
        )
        cleanup = _RunCleanup(
            token.token_id,
            paths,
            self._require_revoke(),
            self._require_wipe(),
        )
        return (
            _PreparedRun(
                run_id=run_id,
                workflow_name=workflow_name,
                isolation=isolation,
                paths=paths,
                config=config,
                token=token,
                contract=contract,
                guest_port=cast(int, isolation.guest_port),
            ),
            workflow,
            inputs,
            cleanup,
        )

    def _prepare_paths(self, runs_dir: Path) -> FirecrackerRunPaths:
        exchange = Path(runs_dir)
        if exchange.exists() and exchange.is_symlink():
            raise FirecrackerAdapterError("runs_dir must not be a symlink")
        if not exchange.exists():
            exchange.mkdir(parents=True, exist_ok=True)
        if not exchange.is_dir():
            raise FirecrackerAdapterError(f"runs_dir is not a directory: {exchange}")
        exchange = exchange.resolve()
        run_dir = exchange.parent
        if run_dir == exchange:
            raise FirecrackerAdapterError("runs_dir must be a run-local exchange directory")
        if run_dir.exists() and run_dir.is_symlink():
            raise FirecrackerAdapterError("run directory must not be a symlink")
        if self.runs_root is not None:
            root = self.runs_root.resolve()
            try:
                exchange.relative_to(root)
            except ValueError as exc:
                raise FirecrackerAdapterError("runs_dir is outside the adapter runs_root") from exc
        api = run_dir / "firecracker.api.sock"
        vsock = run_dir / "firecracker.vsock.sock"
        if api == vsock:
            raise FirecrackerAdapterError("run-local Firecracker socket path is invalid")
        for path in (api, vsock):
            if path.exists() and not (path.is_socket() or path.is_file()):
                raise FirecrackerAdapterError(f"refusing to reuse non-file socket path: {path}")
        return FirecrackerRunPaths(run_dir, exchange, api, vsock)

    def _validate_config(self, config: FirecrackerConfig) -> None:
        if self.validate_socket_paths:
            config.validate()
            return
        # Keep artifact and resource admission active for injected fakes while
        # allowing their long temporary socket prefixes.
        for name, path in (
            ("Firecracker binary", config.binary),
            ("kernel image", config.kernel_image),
            ("rootfs", config.rootfs),
        ):
            if not path.is_file():
                raise FirecrackerError(f"{name} does not exist: {path}")
        if not os.access(config.binary, os.X_OK):
            raise FirecrackerError(f"Firecracker binary is not executable: {config.binary}")
        if config.guest_cid < 3 or config.guest_cid > 0xFFFFFFFF:
            raise FirecrackerError("guest CID must be in the Firecracker range")
        if config.vcpu_count < 1 or config.mem_size_mib < 128:
            raise FirecrackerError("vcpu_count and mem_size_mib are below safe minimums")
        if config.api_socket == config.vsock_socket:
            raise FirecrackerError("API and vsock sockets must be distinct")

    def _build_config(
        self, isolation: IsolationProfile, paths: FirecrackerRunPaths
    ) -> FirecrackerConfig:
        kernel = _required_profile_path(isolation.kernel_image, "kernel_image")
        rootfs = _required_profile_path(isolation.rootfs, "rootfs")
        guest_cid = cast(int, isolation.guest_cid)
        vcpu_count = self.vcpu_count if self.vcpu_count is not None else _parse_cpu(isolation.cpu)
        mem_size = (
            self.mem_size_mib if self.mem_size_mib is not None else _parse_memory(isolation.memory)
        )
        return FirecrackerConfig(
            binary=self.binary,
            kernel_image=kernel,
            rootfs=rootfs,
            api_socket=paths.api_socket,
            vsock_socket=paths.vsock_socket,
            guest_cid=guest_cid,
            vcpu_count=vcpu_count,
            mem_size_mib=mem_size,
            boot_args=self.boot_args,
            rootfs_format=cast(Any, isolation.rootfs_format),
        )

    def _load_token(self, value: object) -> CapabilityToken:
        loaded: CapabilityToken | Mapping[str, Any]
        if self._token_loader is not None:
            loaded = self._token_loader(value)
        elif isinstance(value, CapabilityToken):
            loaded = value
        else:
            loaded = _read_json_map(cast(Path, value), "capability token")
        if isinstance(loaded, CapabilityToken):
            token = loaded
        else:
            try:
                token = CapabilityToken.verify(
                    loaded,
                    signing_key=self.signing_key,
                    signer=self.signer,
                    now=self._now() if self._now is not None else None,
                )
            except CapabilityError as exc:
                raise FirecrackerAdapterError(f"capability token admission failed: {exc}") from exc
        return token

    def _validate_token_binding(
        self, token: CapabilityToken, *, run_id: str, lease_id: str
    ) -> None:
        if token.run_id != run_id:
            raise FirecrackerAdapterError("capability token run_id does not match the run")
        if token.lease_id != lease_id:
            raise FirecrackerAdapterError("capability token lease_id does not match the lease")
        for field, expected in (
            ("host_id", self.host_id),
            ("repository", self.repository),
            ("branch", self.branch),
            ("base_sha", self.base_sha),
        ):
            if expected is not None and getattr(token, field) != expected:
                raise FirecrackerAdapterError(f"capability token {field} does not match adapter")
        if not token.nonce:
            raise FirecrackerAdapterError("capability token nonce is required")

    @staticmethod
    def _validate_lease(data: Mapping[str, Any], token: CapabilityToken) -> None:
        value = _first(data, "lease_id", "leaseId", "id")
        if value is not None and value != token.lease_id:
            raise FirecrackerAdapterError("lease file identity does not match capability token")

    @staticmethod
    def _validate_attestation(
        data: Mapping[str, Any],
        *,
        token: CapabilityToken,
        run_id: str,
        image_digest: str,
        exchange_dir: Path,
    ) -> None:
        checks = (
            (("lease_id", "leaseId"), token.lease_id),
            (("run_id", "runId"), run_id),
            (("image_digest", "imageDigest"), image_digest),
        )
        for names, expected in checks:
            value = _first(data, *names)
            if value is not None and value != expected:
                raise FirecrackerAdapterError("runtime attestation identity mismatch")
        output_exchange = _first(data, "output_exchange", "outputExchange")
        if output_exchange is not None and Path(str(output_exchange)).resolve() != exchange_dir:
            raise FirecrackerAdapterError("runtime attestation exchange does not match the run")

    def _artifact_digest(self, isolation: IsolationProfile, image_digest: str) -> str:
        if self.artifact_digest is not None:
            return self.artifact_digest
        # A canonical image digest is the preferred guest-artifact binding.  If
        # the caller uses a distinct image/rootfs identity, hash the admitted
        # read-only rootfs as the concrete artifact instead.
        suffix = image_digest.split(":", 1)[1]
        rootfs = _required_profile_path(isolation.rootfs, "rootfs")
        try:
            hasher = hashlib.sha256()
            with rootfs.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    hasher.update(chunk)
            rootfs_digest = hasher.hexdigest()
        except OSError as exc:
            raise FirecrackerAdapterError(f"unable to hash admitted rootfs: {rootfs}") from exc
        # Prefer the explicit immutable image binding, but retaining a rootfs
        # hash is useful when an image reference and guest bundle differ.
        return suffix if suffix == rootfs_digest else rootfs_digest

    def _contract(
        self,
        *,
        token: CapabilityToken,
        run_id: str,
        workflow_name: str,
        isolation: IsolationProfile,
        paths: FirecrackerRunPaths,
        image_digest: str,
        artifact_digest: str,
        attestation: Mapping[str, Any],
        authorization_env: Mapping[str, str],
    ) -> dict[str, object]:
        storage = isolation.storage_policy.model_dump(mode="json")
        network = isolation.network_policy.model_dump(mode="json")
        contract: dict[str, object] = {
            "schema": "testudo.guest.contract.v1",
            "run_id": run_id,
            "lease_id": token.lease_id,
            "token_id": token.token_id,
            "host_id": token.host_id,
            "vm_id": token.vm_id,
            "repository": token.repository,
            "branch": token.branch,
            "base_sha": token.base_sha,
            "nonce": token.nonce,
            "image_digest": image_digest,
            "artifact_digest": artifact_digest,
            "workflow_name": workflow_name,
            "policy_digest": isolation.policy_digest,
            "storage_policy": storage,
            "network_policy": network,
            "network": "none",
            "read_only": True,
            "host_mounts": [],
            "guest_paths": {
                "workspace": isolation.storage_policy.workspace,
                "inputs": isolation.storage_policy.inputs,
            },
            # The host path is deliberately absent.  The guest only knows the
            # declared guest exchange path and receives maps over vsock.
            "output_exchange": isolation.storage_policy.workspace,
            "exchange_path": isolation.storage_policy.workspace,
            "authorization_keys": sorted(authorization_env),
            "containment": containment_contract(),
        }
        attestation_hash = _first(attestation, "attestation_hash", "attestationHash")
        if isinstance(attestation_hash, str) and attestation_hash:
            contract["attestation_hash"] = attestation_hash
        # Keep host-owned transient paths available to the launcher only; no
        # path is copied into the guest contract or mounted as a drive.
        del paths
        return contract

    def _launch_binding(
        self,
        prepared: _PreparedRun,
        cleanup: _RunCleanup,
        **kwargs: object,
    ) -> HostWorkerAdapter:
        for name, expected in (
            ("run_id", prepared.run_id),
            ("token_id", prepared.token.token_id),
            ("nonce", prepared.token.nonce),
        ):
            if kwargs.get(name) != expected:
                raise FirecrackerAdapterError(f"launcher identity mismatch: {name}")
        lifecycle: WorkerLifecycle | None = None
        try:
            launch_kwargs: dict[str, object] = {
                "revoke_token": cleanup.revoke,
                "wipe_vm": cleanup.wipe,
                "signing_key": self.signing_key,
                "signer": self.signer,
                "event_sink": lambda _event: None,
                "now": self._now,
                "startup_timeout": self.startup_timeout,
                "expected_identity": {
                    field: getattr(prepared.token, field) for field in _TOKEN_IDENTITY_FIELDS
                },
            }
            if self._popen is not None:
                launch_kwargs["popen"] = self._popen
            lifecycle = cast(
                WorkerLifecycle,
                _call_compatible(
                    self._worker_launcher,
                    prepared.config,
                    prepared.token,
                    **launch_kwargs,
                ),
            )
            connector = self._connector(prepared.config, prepared.guest_port)
            broker = cast(
                _BrokerLike,
                _call_compatible(
                    self._broker_opener,
                    prepared.config,
                    run_id=prepared.run_id,
                    token_id=prepared.token.token_id,
                    nonce=prepared.token.nonce,
                    contract=prepared.contract,
                    guest_port=prepared.guest_port,
                    connector=connector,
                ),
            )
            broker = _BrokerProxy(
                broker,
                run_id=prepared.run_id,
                token_id=prepared.token.token_id,
                nonce=prepared.token.nonce,
            )
            return _AdapterBinding(lifecycle, broker)
        except BaseException as exc:
            # launch_worker already covers its own process/API failure paths;
            # custom injected launchers may not.  If the broker fails after a
            # lifecycle was returned, stop it first so its process tree cannot
            # outlive the adapter failure boundary.
            if lifecycle is not None:
                try:
                    lifecycle.stop("broker_open_failure")
                except BaseException as stop_error:
                    exc.add_note(
                        "Firecracker adapter lifecycle stop failed: "
                        f"{type(stop_error).__name__}: {stop_error}"
                    )
            _best_effort_cleanup(exc, cleanup.cleanup_without_worker)
            raise

    def _connector(
        self, config: FirecrackerConfig, guest_port: int
    ) -> FirecrackerVsockConnector | object | None:
        if self._connector_factory is not None:
            return self._connector_factory(config, guest_port)
        if not self.validate_socket_paths:
            return None
        return FirecrackerVsockConnector(
            cast(Path, config.vsock_socket),
            guest_port=guest_port,
            socket_factory=cast(Any, self._socket_factory),
        )

    @staticmethod
    def _validate_microvm_profile(isolation: IsolationProfile) -> None:
        if isolation.primitive != "microvm":
            raise FirecrackerAdapterError("Firecracker adapter requires primitive='microvm'")
        if isolation.network != "none":
            raise FirecrackerAdapterError("Firecracker microVM requires network='none'")
        if not isolation.read_only:
            raise FirecrackerAdapterError("Firecracker microVM requires read_only=True")
        policy = isolation.network_policy
        if policy.purpose != "none" or policy.egress_hosts or policy.egress_ports or policy.methods:
            raise FirecrackerAdapterError("Firecracker adapter admits only the no-network policy")
        if isolation.storage_policy.host_scope != "run_local":
            raise FirecrackerAdapterError("Firecracker storage must be run_local")
        if isolation.storage_policy.host_mounts:
            raise FirecrackerAdapterError("arbitrary host mounts are not allowed")
        for name in ("kernel_image", "rootfs", "vsock_socket"):
            value = getattr(isolation, name)
            if not isinstance(value, str) or not value:
                raise FirecrackerAdapterError(f"microVM {name} is required")
        if isolation.guest_cid is None or isolation.guest_port is None:
            raise FirecrackerAdapterError("microVM guest CID and port are required")

    def _require_revoke(self) -> Callable[[str], None]:
        if self._revoke_external is None:
            raise FirecrackerAdapterError("a host token-revocation callback is required")
        return self._revoke_external

    def _require_wipe(self) -> Callable[[], None]:
        if self._wipe_external is None:
            raise FirecrackerAdapterError("a host VM-wipe callback is required")
        return self._wipe_external


# A stable sentinel used only to serialize concurrent admission.  It is never
# dereferenced as a cleanup object.
_ACTIVE_SENTINEL = object()


def _required_profile_path(value: str | None, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise FirecrackerAdapterError(f"microVM {field} is required")
    return Path(value)


def _require_digest(value: str | None, *, field: str) -> None:
    if not isinstance(value, str) or fullmatch(r"sha256:" + _SHA256, value) is None:
        raise FirecrackerAdapterError(f"{field} must be an immutable sha256 digest")


def _require_artifact_digest(value: str) -> None:
    if fullmatch(_SHA256, value) is None:
        raise FirecrackerAdapterError("artifact_digest must be a lowercase SHA-256")


def _parse_cpu(value: str) -> int:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise FirecrackerAdapterError("microVM cpu must be a positive whole number") from exc
    if parsed < 1 or not parsed.is_integer():
        raise FirecrackerAdapterError("microVM cpu must be a positive whole number")
    return int(parsed)


def _parse_memory(value: str) -> int:
    text = value.strip().lower()
    units = (("gib", 1024), ("gb", 1024), ("g", 1024), ("mib", 1), ("mb", 1), ("m", 1))
    multiplier = 1
    for suffix, factor in units:
        if text.endswith(suffix):
            text = text[: -len(suffix)].strip()
            multiplier = factor
            break
    try:
        parsed = float(text) * multiplier
    except (TypeError, ValueError) as exc:
        raise FirecrackerAdapterError("microVM memory is invalid") from exc
    if parsed < 128 or not parsed.is_integer():
        raise FirecrackerAdapterError("microVM memory must be at least 128 MiB")
    return int(parsed)


def _read_json_map(path: Path, label: str) -> dict[str, Any]:
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        raise FirecrackerAdapterError(f"{label} file does not exist: {target}")
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FirecrackerAdapterError(f"{label} is not valid JSON: {target}") from exc
    if not isinstance(value, Mapping):
        raise FirecrackerAdapterError(f"{label} must be a JSON object")
    return dict(value)


def _read_optional_map(value: Path | Mapping[str, Any], label: str) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return _read_json_map(value, label)


def _read_inputs(inputs_dir: Path | None) -> Mapping[str, Any]:
    if inputs_dir is None:
        return {}
    target = Path(inputs_dir)
    if target.is_symlink():
        raise FirecrackerAdapterError("inputs_dir must not be a symlink")
    if target.is_file():
        return _read_json_map(target, "inputs")
    if not target.is_dir():
        raise FirecrackerAdapterError(f"inputs directory does not exist: {target}")
    candidates = [target / name for name in ("inputs.json", "input.json", "values.json")]
    existing = [
        candidate for candidate in candidates if candidate.is_file() and not candidate.is_symlink()
    ]
    if not existing:
        json_files = sorted(
            candidate
            for candidate in target.glob("*.json")
            if candidate.is_file() and not candidate.is_symlink()
        )
        if len(json_files) == 1:
            existing = json_files
    if not existing:
        return {}
    return _read_json_map(existing[0], "inputs")


def _first(data: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in data:
            return data[name]
    return None


def _best_effort_cleanup(primary: BaseException, operation: Callable[[], None]) -> None:
    try:
        operation()
    except BaseException as cleanup_error:
        primary.add_note(
            f"Firecracker adapter cleanup failed: {type(cleanup_error).__name__}: {cleanup_error}"
        )


def _call_compatible(function: Callable[..., object], *args: object, **kwargs: object) -> object:
    """Call an injected fake while retaining the production keyword contract."""
    try:
        signature = inspect.signature(function)
    except (TypeError, ValueError):
        return function(*args, **kwargs)
    parameters = signature.parameters
    if any(parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()):
        return function(*args, **kwargs)
    filtered = {name: value for name, value in kwargs.items() if name in parameters}
    return function(*args, **filtered)


# Public aliases for callers that name the Linux implementation explicitly.
LinuxFirecrackerAdapter = FirecrackerAdapter
FirecrackerHostAdapter = FirecrackerAdapter


def create_firecracker_adapter(*args: object, **kwargs: object) -> FirecrackerAdapter:
    """Construct a Firecracker adapter without exposing implementation details."""
    return FirecrackerAdapter(*args, **kwargs)  # type: ignore[arg-type]


build_firecracker_adapter = create_firecracker_adapter

__all__ = [
    "AdapterError",
    "FirecrackerAdapter",
    "FirecrackerAdapterError",
    "FirecrackerHostAdapter",
    "FirecrackerRunPaths",
    "LinuxFirecrackerAdapter",
    "RunPaths",
    "build_firecracker_adapter",
    "create_firecracker_adapter",
]
