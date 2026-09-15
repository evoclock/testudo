# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bounded host-side broker session for the Testudo guest protocol.

The broker wraps an already-connected Firecracker vsock or macOS
virtio-socket connection. It does not create listeners, configure network
devices, launch guests, or grant capabilities. The guest bootstrap is a
protocol contract represented by the explicit state machine here; a later
host adapter supplies the actual connection and guest process.
"""

from __future__ import annotations

import socket
from collections.abc import Mapping
from typing import Any, Protocol, cast

from testudo.runtime.transport import (
    MAX_FRAME_BYTES,
    Frame,
    TransportError,
    read_frame,
    write_frame,
)

_HOST_KINDS = frozenset({"bootstrap", "run", "stop"})
_GUEST_KINDS = frozenset({"ready", "stdout", "stderr", "result", "error", "receipt"})
_STREAM_KINDS = frozenset({"stdout", "stderr", "receipt"})


class BrokerError(TransportError):
    """A broker frame or state transition violates the guest contract."""


class ConnectedSocket(Protocol):
    """Minimal interface required from an already-connected socket."""

    def sendall(self, data: bytes) -> None:
        """Send all bytes or raise an OS error."""

    def recv(self, size: int) -> bytes:
        """Read up to ``size`` bytes, returning empty on peer close."""

    def close(self) -> None:
        """Close the connection."""


class BrokerSession:
    """Validate and sequence one host/guest broker conversation."""

    def __init__(
        self,
        sock: ConnectedSocket,
        *,
        run_id: str,
        token_id: str,
        nonce: str,
        max_bytes: int = MAX_FRAME_BYTES,
    ) -> None:
        if not all(isinstance(value, str) and value for value in (run_id, token_id, nonce)):
            raise BrokerError("run_id, token_id and nonce are required")
        if max_bytes <= 0 or max_bytes > MAX_FRAME_BYTES:
            raise BrokerError("max_bytes is outside the transport limit")
        self._sock = sock
        self.run_id = run_id
        self.token_id = token_id
        self.nonce = nonce
        self.max_bytes = max_bytes
        self._send_sequence = 0
        self._receive_sequence = 0
        self._state = "new"
        self._closed = False

    @property
    def state(self) -> str:
        """Return the current protocol state."""
        return self._state

    def send(self, kind: str, payload: Mapping[str, Any]) -> Frame:
        """Send one legal host-to-guest frame and advance its sequence."""
        if self._closed:
            raise BrokerError("broker session is closed")
        if kind not in _HOST_KINDS:
            raise BrokerError(f"host frame kind is not allowed: {kind}")
        if not isinstance(payload, Mapping):
            raise BrokerError("host frame payload must be a map")
        self._check_send_state(kind)
        frame = Frame(
            sequence=self._send_sequence,
            run_id=self.run_id,
            token_id=self.token_id,
            nonce=self.nonce,
            kind=kind,
            payload=dict(payload),
        )
        try:
            write_frame(cast(socket.socket, self._sock), frame, max_bytes=self.max_bytes)
        except (OSError, TransportError) as exc:
            self._state = "terminal"
            raise BrokerError(f"failed to send {kind} frame: {exc}") from exc
        self._send_sequence += 1
        if kind == "run":
            self._state = "running"
        elif kind == "stop":
            self._state = "stop_requested"
        return frame

    def receive(self) -> Frame:
        """Read and validate one guest-to-host frame."""
        if self._closed:
            raise BrokerError("broker session is closed")
        try:
            frame = read_frame(cast(socket.socket, self._sock), max_bytes=self.max_bytes)
        except (OSError, TransportError) as exc:
            self._state = "terminal"
            raise BrokerError(f"failed to read guest frame: {exc}") from exc
        if frame.run_id != self.run_id or frame.token_id != self.token_id:
            self._reject("guest frame identity does not match session")
        if frame.nonce != self.nonce:
            self._reject("guest frame nonce does not match session")
        if frame.sequence != self._receive_sequence:
            self._reject(
                f"guest frame sequence is {frame.sequence}, expected {self._receive_sequence}"
            )
        if frame.kind not in _GUEST_KINDS:
            self._reject(f"guest frame kind is not allowed: {frame.kind}")
        self._check_receive_state(frame.kind)
        self._receive_sequence += 1
        if frame.kind == "ready":
            self._state = "ready"
        elif frame.kind in {"result", "error"}:
            self._state = "terminal"
        return frame

    def bootstrap(self, contract: Mapping[str, Any]) -> Frame:
        """Send the read-only guest contract and require a ready response."""
        self.send("bootstrap", contract)
        ready = self.receive()
        if ready.kind != "ready":
            self._reject(f"bootstrap expected ready, received {ready.kind}")
        return ready

    def run(self, workflow: Mapping[str, Any], inputs: Mapping[str, Any]) -> Frame:
        """Send one admitted workflow and its read-only inputs."""
        if not isinstance(workflow, Mapping) or not isinstance(inputs, Mapping):
            raise BrokerError("workflow and inputs must be maps")
        return self.send("run", {"workflow": dict(workflow), "inputs": dict(inputs)})

    def stop(self, reason: str = "operator_stop") -> Frame:
        """Request guest termination without widening the protocol scope."""
        if not isinstance(reason, str) or not reason:
            raise BrokerError("stop reason is required")
        return self.send("stop", {"reason": reason})

    def close(self) -> None:
        """Close the connection idempotently and mark the session closed."""
        if self._closed:
            return
        self._closed = True
        self._state = "closed"
        self._sock.close()

    def _check_send_state(self, kind: str) -> None:
        allowed = {
            "bootstrap": {"new"},
            "run": {"ready"},
            "stop": {"ready", "running"},
        }
        if self._state not in allowed[kind]:
            raise BrokerError(f"cannot send {kind} in state {self._state}")

    def _check_receive_state(self, kind: str) -> None:
        allowed = {
            "ready": {"new"},
            **{stream_kind: {"running", "stop_requested"} for stream_kind in _STREAM_KINDS},
            "result": {"running", "stop_requested"},
            "error": {"running", "stop_requested"},
        }
        if self._state not in allowed[kind]:
            self._reject(f"cannot receive {kind} in state {self._state}")

    def _reject(self, reason: str) -> None:
        self._state = "terminal"
        raise BrokerError(reason)


__all__ = ["BrokerError", "BrokerSession", "ConnectedSocket"]
