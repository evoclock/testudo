# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Pure guest-side protocol/bootstrap seam for the Testudo broker.

This module is suitable for a later admitted guest artifact. It validates
the host bootstrap and command stream, emits context-bound guest frames,
and never launches a process, opens a listener, or grants capabilities.
"""

from __future__ import annotations

import socket
from collections.abc import Mapping
from typing import Any, NoReturn, cast

from testudo.runtime.broker import ConnectedSocket
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
_IDENTITY_FIELDS = ("run_id", "token_id", "nonce")


class GuestError(TransportError):
    """A host command or guest protocol transition violates the contract."""


class GuestSession:
    """Validate one guest-side conversation on an existing socket."""

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
            raise GuestError("run_id, token_id and nonce are required")
        if max_bytes <= 0 or max_bytes > MAX_FRAME_BYTES:
            raise GuestError("max_bytes is outside the transport limit")
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
        """Return the current guest protocol state."""
        return self._state

    @classmethod
    def accept_bootstrap(
        cls,
        sock: ConnectedSocket,
        *,
        max_bytes: int = MAX_FRAME_BYTES,
    ) -> tuple[GuestSession, Mapping[str, Any]]:
        """Accept the first host frame and create a context-bound session.

        A guest process cannot receive the per-run identity through its static
        artifact. This entrypoint consumes the bootstrap frame first, derives
        the identity from that frame, and then continues through the same
        ``GuestSession`` state machine used by the known-identity tests.
        """
        try:
            frame = read_frame(cast(socket.socket, sock), max_bytes=max_bytes)
        except (OSError, TransportError) as exc:
            raise GuestError(f"failed to read host bootstrap: {exc}") from exc
        if frame.kind != "bootstrap":
            raise GuestError(f"guest bootstrap expected bootstrap, received {frame.kind}")
        identity: dict[str, str] = {}
        for field in _IDENTITY_FIELDS:
            value = frame.payload.get(field)
            if not isinstance(value, str) or not value:
                raise GuestError(f"bootstrap {field} is required")
            identity[field] = value
        session = cls(sock, max_bytes=max_bytes, **identity)
        session._receive_sequence = 1
        session._validate_bootstrap(frame)
        session.send("ready", {"protocol": "testudo.vsock.frame.v1"})
        return session, dict(frame.payload)

    def receive_command(self) -> Frame:
        """Read and validate one host bootstrap, run or stop command."""
        if self._closed:
            raise GuestError("guest session is closed")
        try:
            frame = read_frame(cast(socket.socket, self._sock), max_bytes=self.max_bytes)
        except (OSError, TransportError) as exc:
            self._state = "terminal"
            raise GuestError(f"failed to read host frame: {exc}") from exc
        if frame.run_id != self.run_id or frame.token_id != self.token_id:
            self._reject("host frame identity does not match session")
        if frame.nonce != self.nonce:
            self._reject("host frame nonce does not match session")
        if frame.sequence != self._receive_sequence:
            self._reject(
                f"host frame sequence is {frame.sequence}, expected {self._receive_sequence}"
            )
        if frame.kind not in _HOST_KINDS:
            self._reject(f"host frame kind is not allowed: {frame.kind}")
        self._check_receive_state(frame.kind)
        self._receive_sequence += 1
        if frame.kind == "run":
            self._state = "running"
        elif frame.kind == "stop":
            self._state = "stop_requested"
        return frame

    def bootstrap(self, ready_payload: Mapping[str, Any] | None = None) -> Frame:
        """Accept host bootstrap context and emit a bound ``ready`` frame."""
        frame = self.receive_command()
        self._validate_bootstrap(frame)
        payload = dict(ready_payload or {"protocol": "testudo.vsock.frame.v1"})
        return self.send("ready", payload)

    def _validate_bootstrap(self, frame: Frame) -> None:
        """Validate the bootstrap frame against this session's identity."""
        if frame.kind != "bootstrap":
            self._reject(f"guest bootstrap expected bootstrap, received {frame.kind}")
        if frame.sequence != 0:
            self._reject("guest bootstrap expected sequence zero")
        for field in _IDENTITY_FIELDS:
            if frame.payload.get(field) != getattr(self, field):
                self._reject(f"bootstrap {field} does not match session")

    def receive_run(self) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        """Receive one run command and return its workflow and inputs maps."""
        frame = self.receive_command()
        if frame.kind != "run":
            self._reject(f"guest run expected run, received {frame.kind}")
        workflow = frame.payload.get("workflow")
        inputs = frame.payload.get("inputs")
        if not isinstance(workflow, Mapping) or not isinstance(inputs, Mapping):
            self._reject("run payload requires workflow and inputs maps")
        return dict(workflow), dict(inputs)

    def send(self, kind: str, payload: Mapping[str, Any]) -> Frame:
        """Send one legal guest-to-host frame and advance its sequence."""
        if self._closed:
            raise GuestError("guest session is closed")
        if kind not in _GUEST_KINDS:
            raise GuestError(f"guest frame kind is not allowed: {kind}")
        if not isinstance(payload, Mapping):
            raise GuestError("guest frame payload must be a map")
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
            raise GuestError(f"failed to send guest frame: {exc}") from exc
        self._send_sequence += 1
        if kind in {"result", "error"}:
            self._state = "terminal"
        elif kind == "ready":
            self._state = "ready"
        return frame

    def send_stdout(self, chunk: str) -> Frame:
        """Send one bounded stdout chunk."""
        if not isinstance(chunk, str):
            raise GuestError("stdout chunk must be text")
        return self.send("stdout", {"chunk": chunk})

    def send_stderr(self, chunk: str) -> Frame:
        """Send one bounded stderr chunk."""
        if not isinstance(chunk, str):
            raise GuestError("stderr chunk must be text")
        return self.send("stderr", {"chunk": chunk})

    def send_receipt(self, receipt: Mapping[str, Any]) -> Frame:
        """Send one host-verifiable receipt reference."""
        return self.send("receipt", receipt)

    def send_result(self, result: Mapping[str, Any]) -> Frame:
        """Send a terminal successful result."""
        return self.send("result", result)

    def send_error(self, error: Mapping[str, Any]) -> Frame:
        """Send a terminal failed result."""
        return self.send("error", error)

    def close(self) -> None:
        """Close the existing connection idempotently."""
        if self._closed:
            return
        self._closed = True
        self._state = "closed"
        self._sock.close()

    def _check_receive_state(self, kind: str) -> None:
        allowed = {
            "bootstrap": {"new"},
            "run": {"ready"},
            "stop": {"ready", "running"},
        }
        if self._state not in allowed[kind]:
            self._reject(f"cannot receive {kind} in state {self._state}")

    def _check_send_state(self, kind: str) -> None:
        allowed = {
            "ready": {"new"},
            **{stream_kind: {"running", "stop_requested"} for stream_kind in _STREAM_KINDS},
            "result": {"running", "stop_requested"},
            "error": {"running", "stop_requested"},
        }
        if self._state not in allowed[kind]:
            raise GuestError(f"cannot send {kind} in state {self._state}")

    def _reject(self, reason: str) -> NoReturn:
        self._state = "terminal"
        raise GuestError(reason)


__all__ = ["GuestError", "GuestSession"]
