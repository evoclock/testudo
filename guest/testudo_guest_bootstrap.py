#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Workflow-capable Testudo guest bootstrap.

This is the guest-side entrypoint for an admitted Firecracker/vsock bundle. It
runs the workflow sent over the already-connected broker socket inside the
Testudo ``Workflow``/``Executor`` path, then emits bounded output, a canonical
result hash, and a receipt bound to the admitted guest artifact digest.

The bootstrap does not create a listener, mount host paths, grant capabilities,
or enable network access. The host supplies the connected vsock stream and the
run-scoped contract; the rootfs and any writable run path are admitted
separately by the host adapter.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
from collections.abc import Mapping
from typing import Any

from testudo.orchestrator import Executor, Workflow, resolve_permissions
from testudo.runtime.broker import ConnectedSocket
from testudo.runtime.containment import containment_contract
from testudo.runtime.guest import GuestError, GuestSession

GUEST_PORT = 10000
GUEST_RECEIPT_SCHEMA = "testudo.guest.receipt.v1"
STDIO_GUEST_PROTOCOL = "testudo.vsock.frame.v1"


class GuestBootstrapError(GuestError):
    """A workflow or guest-artifact contract cannot be executed."""


def _canonical(value: Mapping[str, object]) -> bytes:
    """Match the host controller's canonical JSON representation."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise GuestBootstrapError("guest result is not canonical JSON") from exc


def _sha256(value: Mapping[str, object]) -> str:
    """Hash one canonical result mapping."""
    return hashlib.sha256(_canonical(value)).hexdigest()


def _artifact_digest(contract: Mapping[str, Any]) -> str:
    """Require the host to bind the receipt to the admitted guest bundle."""
    digest = contract.get("artifact_digest")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise GuestBootstrapError("bootstrap artifact_digest must be a lowercase SHA-256")
    return digest


def _active_containment(contract: Mapping[str, Any]) -> dict[str, object] | None:
    """Validate the host-bound monitor identity and require guest activation."""
    supplied = contract.get("containment")
    if supplied is None:
        return None
    expected = containment_contract()
    if not isinstance(supplied, Mapping) or dict(supplied) != expected:
        raise GuestBootstrapError(
            "bootstrap containment contract does not match the guest artifact"
        )
    digest = expected["taxonomy_sha256"]
    if os.environ.get("TESTUDO_CONTAINMENT_ACTIVE") != digest:
        raise GuestBootstrapError("guest containment monitor is not active")
    return {
        **expected,
        "monitor_active": True,
    }


def _result_payload(results: Mapping[str, Any]) -> dict[str, object]:
    """Convert executor results into a deterministic, JSON-bound result."""
    steps: dict[str, object] = {}
    failed = False
    for step_id, result in results.items():
        error = result.error
        failed = failed or error is not None
        steps[step_id] = {
            "id": result.id,
            "output": result.output,
            "skipped": result.skipped,
            "error": error,
        }
    return {"exit_status": 1 if failed else 0, "steps": steps}


def _send_failure(session: GuestSession, exc: Exception) -> None:
    """Send bounded diagnostic frames while preserving the terminal error."""
    message = f"{type(exc).__name__}: {exc}"
    try:
        session.send_stderr(message + "\n")
    except GuestError:
        return
    try:
        session.send_error({"error": message})
    except GuestError:
        return


class StdioGuestSocket:
    """Pipe-backed duplex transport for native ``container`` execution.

    The native adapter supplies framed protocol bytes on process stdin/stdout.
    File descriptors are borrowed rather than closed so the bootstrap cannot
    accidentally close the process standard streams while serving one run.
    """

    def __init__(self, read_fd: int, write_fd: int) -> None:
        if read_fd < 0 or write_fd < 0:
            raise GuestBootstrapError("stdio file descriptors must be non-negative")
        self._read_fd = read_fd
        self._write_fd = write_fd

    def sendall(self, data: bytes) -> None:
        """Write all framed bytes, handling short pipe writes."""
        if not isinstance(data, bytes):
            raise GuestBootstrapError("stdio transport requires bytes")
        view = memoryview(data)
        while view:
            written = os.write(self._write_fd, view)
            if written <= 0:
                raise GuestBootstrapError("stdio transport made no write progress")
            view = view[written:]

    def recv(self, size: int) -> bytes:
        """Read up to one framed chunk from the guest stdin pipe."""
        if size <= 0:
            raise GuestBootstrapError("stdio read size must be positive")
        return os.read(self._read_fd, size)

    def close(self) -> None:
        """Leave borrowed process descriptors open for the caller."""


def _bind_writable_paths(contract: Mapping[str, Any]) -> None:
    """Export the contract's declared writable guest paths for the monitor.

    The containment watcher's writable allowlist must match the admitted
    run-local storage policy exactly: the declared workspace (and exchange)
    path is sanctioned for workflow-required writes, everything else stays
    deny-by-default. The contract is host-signed and read-only, so the guest
    cannot widen its own allowlist.
    """
    guest_paths = contract.get("guest_paths")
    workspace: object = None
    if isinstance(guest_paths, Mapping):
        workspace = guest_paths.get("workspace")
    if workspace is None:
        workspace = contract.get("workspace")
    if not isinstance(workspace, str) or not workspace.startswith("/"):
        raise GuestBootstrapError("bootstrap contract must declare a workspace guest path")
    os.environ["TESTUDO_GUEST_WORKSPACE"] = workspace
    os.environ["TESTUDO_GUEST_WRITABLE_PATHS"] = f"{workspace} /tmp/session"


def serve(sock: ConnectedSocket) -> None:
    """Serve one real workflow run on an already-connected vsock stream."""
    session, contract = GuestSession.accept_bootstrap(sock)
    try:
        workflow_data, inputs = session.receive_run()
        try:
            artifact_digest = _artifact_digest(contract)
            containment = _active_containment(contract)
            _bind_writable_paths(contract)
            workflow = Workflow.model_validate(dict(workflow_data))
            permissions = resolve_permissions(workflow)
            results = Executor().run(
                workflow,
                dict(inputs),
                permissions,
                run_id=session.run_id,
            )
            result = _result_payload(results)
            result_hash = _sha256(result)
            session.send_stdout(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
            receipt: dict[str, object] = {
                "schema": GUEST_RECEIPT_SCHEMA,
                "run_id": session.run_id,
                "token_id": session.token_id,
                "nonce": session.nonce,
                "result_sha256": result_hash,
                "artifact_digest": artifact_digest,
            }
            if containment is not None:
                receipt["containment"] = containment
            session.send_receipt(receipt)
            session.send_result({**result, "result_sha256": result_hash})
        except Exception as exc:
            _send_failure(session, exc)
    finally:
        session.close()


def main() -> int:
    """Serve one run over explicit stdio or the Firecracker host vsock."""
    mode = os.environ.get("TESTUDO_GUEST_MODE")
    protocol = os.environ.get("TESTUDO_GUEST_PROTOCOL")
    if mode is not None:
        if mode != "stdio":
            raise GuestBootstrapError("unsupported TESTUDO_GUEST_MODE")
        if protocol != STDIO_GUEST_PROTOCOL:
            raise GuestBootstrapError("unsupported TESTUDO_GUEST_PROTOCOL")
        serve(StdioGuestSocket(sys.stdin.fileno(), sys.stdout.fileno()))
        return 0
    if protocol is not None:
        raise GuestBootstrapError("TESTUDO_GUEST_PROTOCOL requires explicit stdio mode")

    family = getattr(socket, "AF_VSOCK", None)
    if family is None:
        raise GuestBootstrapError("guest Python does not expose AF_VSOCK")
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.connect((getattr(socket, "VMADDR_CID_HOST", 2), GUEST_PORT))
        serve(sock)
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
