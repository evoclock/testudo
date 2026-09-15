# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Firecracker/KVM host adapter primitives.

This module owns only the host-side Firecracker process and API boundary. It
never mounts a host workflow, token, repository or final artifact store into a
guest. A caller must provide an already-admitted guest kernel and read-only
rootfs; the guest-side Testudo bootstrap and framed vsock exchange are separate
admission steps.

The API request set deliberately contains no network-interface request. The
only host socket exposed to the guest is an optional virtio-vsock UDS used by
the reviewed broker.
"""

from __future__ import annotations

import http.client
import json
import os
import signal
import socket
import subprocess
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal, Protocol, cast

from testudo.runtime.broker import BrokerSession, ConnectedSocket
from testudo.runtime.capability import CapabilityError, CapabilityToken, SupervisorEvent
from testudo.runtime.signing import TokenSigner
from testudo.runtime.transport import MAX_FRAME_BYTES
from testudo.runtime.worker import VMHandle, WorkerLifecycle


class FirecrackerError(RuntimeError):
    """A Firecracker process or API contract failed."""


@dataclass(frozen=True, slots=True)
class FirecrackerConfig:
    """Immutable host admission parameters for one Firecracker VM."""

    binary: Path
    kernel_image: Path
    rootfs: Path
    api_socket: Path
    vsock_socket: Path | None = None
    guest_cid: int = 3
    vcpu_count: int = 1
    mem_size_mib: int = 2048
    boot_args: str = "console=ttyS0 reboot=k panic=1 pci=off"
    rootfs_format: Literal["ext4", "squashfs"] = "ext4"

    @property
    def resolved_boot_args(self) -> str:
        """Bind the admitted read-only root drive and filesystem format."""
        return f"{self.boot_args} root=/dev/vda ro rootfstype={self.rootfs_format}"

    def validate(self) -> None:
        """Reject missing inputs and unsafe boundary settings before launch."""
        for name, path in (
            ("Firecracker binary", self.binary),
            ("kernel image", self.kernel_image),
            ("rootfs", self.rootfs),
        ):
            if not path.is_file():
                raise FirecrackerError(f"{name} does not exist: {path}")
        if not os.access(self.binary, os.X_OK):
            raise FirecrackerError(f"Firecracker binary is not executable: {self.binary}")
        if self.guest_cid < 3 or self.guest_cid > 0xFFFFFFFF:
            raise FirecrackerError("guest CID must be in the Firecracker range")
        if self.vcpu_count < 1 or self.mem_size_mib < 128:
            raise FirecrackerError("vcpu_count and mem_size_mib are below safe minimums")
        for name, candidate in (
            ("API socket", self.api_socket),
            ("vsock socket", self.vsock_socket),
        ):
            if candidate is None:
                continue
            if len(str(candidate)) >= 104:
                raise FirecrackerError(f"{name} path is too long for AF_UNIX: {candidate}")
        if self.api_socket == self.vsock_socket:
            raise FirecrackerError("API and vsock sockets must be distinct")
        tokens = self.boot_args.split()
        if any(token == "rw" or token.startswith(("root=", "rootfstype=")) for token in tokens):
            raise FirecrackerError("boot_args cannot override the admitted read-only rootfs")

    def argv(self) -> list[str]:
        """Return the minimal Firecracker process argv."""
        return [str(self.binary), "--api-sock", str(self.api_socket)]


@dataclass(frozen=True, slots=True)
class ApiRequest:
    """One deterministic Firecracker API request."""

    path: str
    body: Mapping[str, object]


def build_api_requests(config: FirecrackerConfig) -> tuple[ApiRequest, ...]:
    """Build the no-network Firecracker configuration sequence."""
    requests: list[ApiRequest] = [
        ApiRequest(
            "/machine-config",
            {
                "vcpu_count": config.vcpu_count,
                "mem_size_mib": config.mem_size_mib,
                "smt": False,
                "track_dirty_pages": False,
            },
        ),
        ApiRequest(
            "/boot-source",
            {
                "kernel_image_path": str(config.kernel_image),
                "boot_args": config.resolved_boot_args,
            },
        ),
        ApiRequest(
            "/drives/rootfs",
            {
                "drive_id": "rootfs",
                "path_on_host": str(config.rootfs),
                "is_root_device": True,
                "is_read_only": True,
            },
        ),
    ]
    if config.vsock_socket is not None:
        requests.append(
            ApiRequest(
                "/vsock",
                {"guest_cid": config.guest_cid, "uds_path": str(config.vsock_socket)},
            )
        )
    requests.append(ApiRequest("/actions", {"action_type": "InstanceStart"}))
    return tuple(requests)


class _UnixHTTPConnection(http.client.HTTPConnection):
    """Small stdlib-only HTTP/1.1 client for Firecracker's AF_UNIX API."""

    def __init__(self, socket_path: Path, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(str(self._socket_path))
        except BaseException:
            sock.close()
            raise
        self.sock = sock


class FirecrackerAPI:
    """Minimal typed client for the Firecracker configuration API."""

    def __init__(self, socket_path: Path, *, timeout: float = 5.0) -> None:
        self.socket_path = socket_path
        self.timeout = timeout

    def put(self, path: str, body: Mapping[str, object]) -> None:
        """PUT one JSON request and require a successful 2xx response."""
        connection = _UnixHTTPConnection(self.socket_path, self.timeout)
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        try:
            connection.request(
                "PUT",
                path,
                body=encoded,
                headers={"Content-Type": "application/json", "Content-Length": str(len(encoded))},
            )
            response = connection.getresponse()
            response_body = response.read().decode("utf-8", errors="replace")
        except (OSError, http.client.HTTPException) as exc:
            raise FirecrackerError(f"Firecracker API request failed for {path}: {exc}") from exc
        finally:
            connection.close()
        if not 200 <= response.status < 300:
            raise FirecrackerError(
                f"Firecracker API rejected {path}: {response.status} {response_body}"
            )

    def configure_and_start(self, config: FirecrackerConfig) -> None:
        """Apply the fixed request sequence and start the instance."""
        for request in build_api_requests(config):
            self.put(request.path, request.body)


class _VsockSocket(ConnectedSocket, Protocol):
    """Socket operations needed for Firecracker's host-side vsock handoff."""

    def connect(self, address: str) -> None:
        """Connect to Firecracker's host Unix-domain vsock endpoint."""

    def settimeout(self, timeout: float) -> None:
        """Bound the connection and guest-port handshake."""


@dataclass(frozen=True, slots=True)
class FirecrackerVsockConnector:
    """Connect to Firecracker's UDS and select one guest vsock port.

    Firecracker creates and owns the configured UDS when its ``/vsock`` API
    request is applied. The host connects to that endpoint, sends the text
    request ``CONNECT <port>\n``, and validates Firecracker's ``OK <port>\n``
    acknowledgement before using the framed broker. This class never creates
    a listener, enables networking, or starts a VM.
    """

    socket_path: Path
    guest_port: int = 10000
    timeout: float = 5.0
    socket_factory: Callable[..., _VsockSocket] | None = None

    def __post_init__(self) -> None:
        if len(str(self.socket_path)) >= 104:
            raise FirecrackerError(f"vsock socket path is too long: {self.socket_path}")
        if isinstance(self.guest_port, bool) or not 1 <= self.guest_port <= 0xFFFFFFFF:
            raise FirecrackerError("guest vsock port must be between 1 and 2^32-1")
        if self.timeout <= 0:
            raise FirecrackerError("vsock connection timeout must be positive")

    def connect(self) -> _VsockSocket:
        """Connect and perform Firecracker's guest-port selection handshake."""
        factory = self.socket_factory or cast(Callable[..., _VsockSocket], socket.socket)
        sock = factory(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect(str(self.socket_path))
            sock.sendall(f"CONNECT {self.guest_port}\n".encode("ascii"))
            self._read_ack(sock, self.guest_port)
        except FirecrackerError:
            with suppress(OSError):
                sock.close()
            raise
        except (OSError, UnicodeError, ValueError) as exc:
            with suppress(OSError):
                sock.close()
            raise FirecrackerError(f"unable to connect to Firecracker vsock: {exc}") from exc
        return sock

    @staticmethod
    def _read_ack(sock: _VsockSocket, requested_port: int) -> None:
        """Read and validate Firecracker's line-delimited UDS acknowledgement.

        The acknowledged port must equal the requested guest port. Firecracker
        answers ``OK <port>`` for the port it handed to the guest; a different
        port means the host would frame a guest that is not listening, so the
        handshake fails closed.
        """
        line = bytearray()
        while len(line) <= 64:
            chunk = sock.recv(1)
            if not chunk:
                raise FirecrackerError("Firecracker vsock closed before acknowledgement")
            line.extend(chunk)
            if chunk == b"\n":
                break
        else:
            raise FirecrackerError("Firecracker vsock acknowledgement is too long")
        try:
            fields = bytes(line).decode("ascii").rstrip("\n").split()
        except UnicodeDecodeError as exc:
            raise FirecrackerError("Firecracker vsock acknowledgement is not ASCII") from exc
        if len(fields) != 2 or fields[0] != "OK":
            raise FirecrackerError("Firecracker vsock acknowledgement must be 'OK <port>\n'")
        try:
            assigned_port = int(fields[1], 10)
        except ValueError as exc:
            raise FirecrackerError("Firecracker vsock acknowledgement port is invalid") from exc
        if not 1 <= assigned_port <= 0xFFFFFFFF:
            raise FirecrackerError("Firecracker vsock acknowledgement port is out of range")
        if assigned_port != requested_port:
            raise FirecrackerError(
                "Firecracker vsock acknowledgement port does not match the requested guest port"
            )


def open_broker_session(
    config: FirecrackerConfig,
    *,
    run_id: str,
    token_id: str,
    nonce: str,
    contract: Mapping[str, object],
    guest_port: int = 10000,
    max_bytes: int = MAX_FRAME_BYTES,
    connector: FirecrackerVsockConnector | None = None,
) -> BrokerSession:
    """Connect to an admitted guest and complete the bootstrap handshake.

    The guest must answer the host ``bootstrap`` frame with a context-bound
    ``ready`` frame. A failed handshake closes the connected socket while
    preserving the primary protocol or transport error. The caller remains
    responsible for worker lifecycle termination, token revocation and wipe.
    """
    if not isinstance(contract, Mapping):
        raise FirecrackerError("guest bootstrap contract must be a map")
    bootstrap_contract = dict(contract)
    for identity_field, expected in (("run_id", run_id), ("token_id", token_id), ("nonce", nonce)):
        if not isinstance(expected, str) or not expected:
            raise FirecrackerError(f"bootstrap {identity_field} is required")
        existing = bootstrap_contract.setdefault(identity_field, expected)
        if existing != expected:
            raise FirecrackerError(f"bootstrap {identity_field} does not match the session")
    if connector is None:
        if config.vsock_socket is None:
            raise FirecrackerError("Firecracker vsock socket is required for broker connection")
        connector = FirecrackerVsockConnector(
            config.vsock_socket,
            guest_port=guest_port,
        )
    sock = connector.connect()
    session: BrokerSession | None = None
    try:
        session = BrokerSession(
            sock,
            run_id=run_id,
            token_id=token_id,
            nonce=nonce,
            max_bytes=max_bytes,
        )
        session.bootstrap(bootstrap_contract)
    except BaseException as exc:
        try:
            if session is None:
                sock.close()
            else:
                session.close()
        except BaseException as close_error:
            exc.add_note(
                f"broker bootstrap close failed: {type(close_error).__name__}: {close_error}"
            )
        raise
    return session


_IDENTITY_FIELDS = (
    "run_id",
    "lease_id",
    "host_id",
    "vm_id",
    "repository",
    "branch",
    "base_sha",
)


def _remove_owned_sockets(config: FirecrackerConfig, *, require_socket: bool = False) -> None:
    """Remove this launch's paths, attempting both even if one fails.

    A path is treated as owned after Firecracker has been started, which keeps
    deterministic fake handles (that use regular files) testable.  Callers
    cleaning up without a process handle set ``require_socket`` to retain the
    stale-path safety check.
    """
    failures: list[tuple[Path, BaseException]] = []
    for path in (config.api_socket, config.vsock_socket):
        if path is None or not path.exists():
            continue
        try:
            if require_socket and not path.is_socket():
                raise FirecrackerError(f"refusing to remove non-socket path: {path}")
            path.unlink()
        except BaseException as exc:
            failures.append((path, exc))
    if failures:
        detail = "; ".join(f"{path}: {exc}" for path, exc in failures)
        raise FirecrackerError(f"socket cleanup failed: {detail}") from failures[0][1]


def _add_cleanup_notes(primary: BaseException, failures: list[tuple[str, BaseException]]) -> None:
    """Attach every best-effort cleanup failure to the primary exception."""
    for action, failure in failures:
        primary.add_note(
            f"Firecracker cleanup {action} failed: {type(failure).__name__}: {failure}"
        )


def _attempt_cleanup(
    primary: BaseException, operations: list[tuple[str, Callable[[], None]]]
) -> None:
    """Run all cleanup operations once while preserving ``primary``."""
    failures: list[tuple[str, BaseException]] = []
    for action, operation in operations:
        try:
            operation()
        except BaseException as exc:
            failures.append((action, exc))
    _add_cleanup_notes(primary, failures)


MAX_OUTPUT_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class FirecrackerOutput:
    """Bounded host-observed output from one Firecracker process."""

    stdout: str
    stderr: str
    stdout_truncated: bool = False
    stderr_truncated: bool = False


class _ReadableStream(Protocol):
    def read(self, size: int = -1) -> str | bytes:
        """Read text or bytes until the process stream closes."""


class _OutputCollector:
    """Drain one process stream without allowing unbounded host memory use."""

    def __init__(self, stream: object, *, max_bytes: int = MAX_OUTPUT_BYTES) -> None:
        self._stream = cast(_ReadableStream, stream)
        self._max_bytes = max_bytes
        self._chunks: list[str] = []
        self._size = 0
        self._truncated = False
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def _drain(self) -> None:
        try:
            while True:
                chunk = self._stream.read(64 * 1024)
                if not chunk:
                    return
                text = (
                    chunk.decode("utf-8", errors="replace") if isinstance(chunk, bytes) else chunk
                )
                encoded = text.encode("utf-8")
                with self._lock:
                    remaining = self._max_bytes - self._size
                    if remaining <= 0:
                        self._truncated = True
                        continue
                    if len(encoded) > remaining:
                        text = encoded[:remaining].decode("utf-8", errors="ignore")
                        self._truncated = True
                    self._chunks.append(text)
                    self._size += len(text.encode("utf-8"))
        except (OSError, ValueError):
            # Process teardown can close a pipe while the drain thread is reading.
            return

    def join(self, timeout: float | None) -> None:
        self._thread.join(timeout=timeout)

    def snapshot(self) -> tuple[str, bool]:
        with self._lock:
            return "".join(self._chunks), self._truncated


def _signal_process_tree(
    process: subprocess.Popen[str],
    sig: int,
    fallback: Callable[[], None],
) -> None:
    """Signal a start-new-session process group, with a process fallback."""
    pid = getattr(process, "pid", None)
    if isinstance(pid, int) and pid > 0:
        try:
            os.killpg(pid, sig)
            return
        except ProcessLookupError:
            return
        except PermissionError:
            pass
    fallback()


@dataclass(slots=True)
class FirecrackerHandle:
    """Running Firecracker process with idempotent termination and cleanup."""

    config: FirecrackerConfig
    process: subprocess.Popen[str]
    api: FirecrackerAPI
    _cleaned: bool = False
    _stdout_collector: _OutputCollector | None = field(init=False, default=None, repr=False)
    _stderr_collector: _OutputCollector | None = field(init=False, default=None, repr=False)

    def __post_init__(self) -> None:
        for name in ("stdout", "stderr"):
            stream = getattr(self.process, name, None)
            collector = (
                _OutputCollector(stream)
                if stream is not None and callable(getattr(stream, "read", None))
                else None
            )
            setattr(self, f"_{name}_collector", collector)

    def wait(self, timeout: float | None = None) -> int:
        """Wait for Firecracker and return its host-observed exit status."""
        try:
            status = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise FirecrackerError("Firecracker did not exit before timeout") from exc
        self.collect_output(timeout=1.0)
        return status

    def terminate(self, *, timeout: float = 5.0) -> None:
        """Terminate the VM process tree, escalating to kill on timeout."""
        if self.process.poll() is not None:
            self.collect_output(timeout=timeout)
            return
        try:
            _signal_process_tree(self.process, signal.SIGTERM, self.process.terminate)
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                _signal_process_tree(self.process, signal.SIGKILL, self.process.kill)
                self.process.wait(timeout=timeout)
        finally:
            self.collect_output(timeout=timeout)

    def collect_output(self, *, timeout: float | None = 5.0) -> FirecrackerOutput:
        """Drain available stdout/stderr and return bounded captured output."""
        if timeout is not None and timeout < 0:
            raise ValueError("output collection timeout must not be negative")
        deadline = None if timeout is None else time.monotonic() + timeout
        for collector in (self._stdout_collector, self._stderr_collector):
            if collector is None:
                continue
            remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
            collector.join(remaining)
        stdout, stdout_truncated = (
            ("", False) if self._stdout_collector is None else self._stdout_collector.snapshot()
        )
        stderr, stderr_truncated = (
            ("", False) if self._stderr_collector is None else self._stderr_collector.snapshot()
        )
        return FirecrackerOutput(stdout, stderr, stdout_truncated, stderr_truncated)

    def cleanup(self) -> None:
        """Drain output and remove only the sockets owned by this handle, once."""
        if self._cleaned:
            return
        self._cleaned = True
        try:
            self.collect_output(timeout=0.5)
        finally:
            _remove_owned_sockets(self.config)


def _wait_for_socket(path: Path, process: subprocess.Popen[str], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            raise FirecrackerError(
                f"Firecracker exited before API socket appeared: {process.returncode}"
            )
        time.sleep(0.01)
    raise FirecrackerError(f"Firecracker API socket did not appear: {path}")


def launch(
    config: FirecrackerConfig,
    *,
    popen: Callable[..., subprocess.Popen[str]] = subprocess.Popen,
    startup_timeout: float = 5.0,
) -> FirecrackerHandle:
    """Launch, configure and start one Firecracker instance.

    The caller owns the guest image admission and must call ``terminate`` and
    ``cleanup`` on every path. Stale socket paths are removed only after the
    configuration has been validated and immediately before this launch.
    """
    config.validate()
    config.api_socket.parent.mkdir(parents=True, exist_ok=True)
    if config.vsock_socket is not None:
        config.vsock_socket.parent.mkdir(parents=True, exist_ok=True)
    for path in (config.api_socket, config.vsock_socket):
        if path is not None and path.exists():
            if not path.is_socket():
                raise FirecrackerError(f"refusing to remove non-socket path: {path}")
            path.unlink()
    try:
        process = popen(
            config.argv(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except OSError as exc:
        raise FirecrackerError(f"unable to launch Firecracker: {exc}") from exc
    handle = FirecrackerHandle(config, process, FirecrackerAPI(config.api_socket))
    try:
        _wait_for_socket(config.api_socket, process, startup_timeout)
        handle.api.configure_and_start(config)
    except BaseException as exc:
        _attempt_cleanup(
            exc,
            [("terminate", handle.terminate), ("socket cleanup", handle.cleanup)],
        )
        # ``launch_worker`` needs to know that this function already attempted
        # process/socket cleanup, so it does not invoke either operation twice.
        with suppress(AttributeError, TypeError):
            exc.__dict__["_testudo_launch_cleanup_attempted"] = True
        raise
    return handle


def launch_worker(
    config: FirecrackerConfig,
    token: CapabilityToken,
    *,
    revoke_token: Callable[[str], None],
    wipe_vm: Callable[[], None],
    signing_key: bytes | None = None,
    signer: TokenSigner | None = None,
    event_sink: Callable[[SupervisorEvent], None] | None = None,
    now: Callable[[], datetime] | None = None,
    popen: Callable[..., subprocess.Popen[str]] = subprocess.Popen,
    startup_timeout: float = 5.0,
    expected_identity: Mapping[str, str] | None = None,
) -> WorkerLifecycle:
    """Verify, bind, launch, and supervise one Firecracker worker.

    Verification and optional identity binding happen before any process is
    started.  Once the token is admitted, launch and lifecycle construction are
    one failure boundary: every applicable cleanup operation is attempted once
    and failures are attached to the original exception as notes.  This seam
    does not create transports, wire a runner, or provide a real VM fallback;
    callers still supply an admitted Firecracker configuration and callbacks
    for token revocation and ephemeral-state wipe.
    """
    verified = CapabilityToken.verify(
        token.to_dict(),
        signing_key=signing_key,
        signer=signer,
        now=now() if now is not None else None,
    )
    if expected_identity is not None:
        required_fields = frozenset(_IDENTITY_FIELDS)
        provided_fields = frozenset(expected_identity)
        if provided_fields != required_fields:
            missing = sorted(required_fields - provided_fields)
            unknown = sorted(provided_fields - required_fields)
            detail = []
            if missing:
                detail.append(f"missing={','.join(missing)}")
            if unknown:
                detail.append(f"unknown={','.join(unknown)}")
            raise CapabilityError(
                "expected token identity must contain exactly all identity fields"
                + (f" ({'; '.join(detail)})" if detail else "")
            )
        for field in _IDENTITY_FIELDS:
            expected = expected_identity[field]
            if not isinstance(expected, str) or not expected:
                raise CapabilityError(f"expected token identity field is invalid: {field}")
            if getattr(verified, field) != expected:
                raise CapabilityError(f"capability token identity mismatch: {field}")

    handle: FirecrackerHandle | None = None
    try:
        handle = launch(config, popen=popen, startup_timeout=startup_timeout)
        return WorkerLifecycle(
            cast(VMHandle, handle),
            verified,
            signing_key=signing_key,
            signer=signer,
            revoke_token=revoke_token,
            wipe_vm=wipe_vm,
            event_sink=event_sink,
            now=now,
        )
    except BaseException as exc:
        operations: list[tuple[str, Callable[[], None]]] = [
            ("revoke", lambda: revoke_token(verified.token_id)),
        ]
        if handle is not None:
            operations.extend([("terminate", handle.terminate), ("socket cleanup", handle.cleanup)])
        elif not getattr(exc, "_testudo_launch_cleanup_attempted", False):
            operations.append(
                ("socket cleanup", lambda: _remove_owned_sockets(config, require_socket=True))
            )
        operations.append(("wipe", wipe_vm))
        _attempt_cleanup(exc, operations)
        raise


__all__ = [
    "MAX_OUTPUT_BYTES",
    "ApiRequest",
    "FirecrackerAPI",
    "FirecrackerConfig",
    "FirecrackerError",
    "FirecrackerHandle",
    "FirecrackerOutput",
    "FirecrackerVsockConnector",
    "build_api_requests",
    "launch",
    "launch_worker",
    "open_broker_session",
]
