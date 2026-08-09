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
import socket
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path


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
            {"kernel_image_path": str(config.kernel_image), "boot_args": config.boot_args},
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


@dataclass(slots=True)
class FirecrackerHandle:
    """Running Firecracker process with idempotent termination and cleanup."""

    config: FirecrackerConfig
    process: subprocess.Popen[str]
    api: FirecrackerAPI
    _cleaned: bool = False

    def wait(self, timeout: float | None = None) -> int:
        """Wait for Firecracker and return its host-observed exit status."""
        try:
            return self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise FirecrackerError("Firecracker did not exit before timeout") from exc

    def terminate(self, *, timeout: float = 5.0) -> None:
        """Terminate the VM process, escalating to kill on timeout."""
        if self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=timeout)

    def cleanup(self) -> None:
        """Remove only the sockets owned by this handle."""
        if self._cleaned:
            return
        self._cleaned = True
        for path in (self.config.api_socket, self.config.vsock_socket):
            if path is not None and path.exists():
                path.unlink()


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
    except BaseException:
        handle.terminate()
        handle.cleanup()
        raise
    return handle


__all__ = [
    "ApiRequest",
    "FirecrackerAPI",
    "FirecrackerConfig",
    "FirecrackerError",
    "FirecrackerHandle",
    "build_api_requests",
    "launch",
]
