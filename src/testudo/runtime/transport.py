# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Length-framed canonical-CBOR transport for the host/guest broker.

The socket may be a Firecracker vsock connection or a macOS virtio-socket
connection. This module does not create listeners, enable networking or grant
capabilities. Every frame is bound to one run, token and message nonce and is
subject to a fixed maximum size before decoding.
"""

from __future__ import annotations

import io
import socket
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import cbor2

MAX_FRAME_BYTES = 4 * 1024 * 1024
_LENGTH = struct.Struct(">I")
_SCHEMA = "testudo.vsock.frame.v1"
_KEYS = frozenset({"schema", "sequence", "run_id", "token_id", "nonce", "kind", "payload"})


class TransportError(ValueError):
    """A frame violates the transport contract or the socket ended early."""


@dataclass(frozen=True, slots=True)
class Frame:
    """One authenticated-context message carried by the broker socket."""

    sequence: int
    run_id: str
    token_id: str
    nonce: str
    kind: str
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise TransportError("frame sequence must be non-negative")
        for name, value in (
            ("run_id", self.run_id),
            ("token_id", self.token_id),
            ("nonce", self.nonce),
            ("kind", self.kind),
        ):
            if not isinstance(value, str) or not value:
                raise TransportError(f"frame {name} is required")
        if not isinstance(self.payload, Mapping):
            raise TransportError("frame payload must be a map")

    def to_mapping(self) -> dict[str, object]:
        return {
            "schema": _SCHEMA,
            "sequence": self.sequence,
            "run_id": self.run_id,
            "token_id": self.token_id,
            "nonce": self.nonce,
            "kind": self.kind,
            "payload": dict(self.payload),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> Frame:
        if set(value) != _KEYS:
            raise TransportError("frame keys do not match the canonical schema")
        if value.get("schema") != _SCHEMA:
            raise TransportError("unsupported frame schema")
        sequence = value.get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool):
            raise TransportError("frame sequence must be an integer")
        strings: dict[str, str] = {}
        for name in ("run_id", "token_id", "nonce", "kind"):
            field = value.get(name)
            if not isinstance(field, str) or not field:
                raise TransportError(f"frame {name} is required")
            strings[name] = field
        payload = value.get("payload")
        if not isinstance(payload, Mapping):
            raise TransportError("frame payload must be a map")
        return cls(
            sequence=sequence,
            run_id=strings["run_id"],
            token_id=strings["token_id"],
            nonce=strings["nonce"],
            kind=strings["kind"],
            payload=payload,
        )


def encode_frame(frame: Frame, *, max_bytes: int = MAX_FRAME_BYTES) -> bytes:
    """Encode one frame as canonical CBOR preceded by a 4-byte length."""
    body = cbor2.dumps(frame.to_mapping(), canonical=True)
    if len(body) > max_bytes or len(body) > 0xFFFFFFFF:
        raise TransportError("frame exceeds maximum size")
    return _LENGTH.pack(len(body)) + body


def decode_frame(body: bytes, *, max_bytes: int = MAX_FRAME_BYTES) -> Frame:
    """Decode exactly one canonical-CBOR body without trailing bytes."""
    if not body or len(body) > max_bytes:
        raise TransportError("frame body exceeds maximum size")
    stream = io.BytesIO(body)
    try:
        value = cbor2.CBORDecoder(stream).decode()
    except (TypeError, ValueError, EOFError) as exc:
        raise TransportError("invalid canonical-CBOR frame") from exc
    if stream.read(1):
        raise TransportError("trailing bytes after frame")
    if not isinstance(value, Mapping):
        raise TransportError("frame root must be a map")
    if cbor2.dumps(value, canonical=True) != body:
        raise TransportError("frame is not canonical CBOR")
    return Frame.from_mapping(value)


def _read_exact(sock: socket.socket, size: int) -> bytes:
    parts: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise TransportError("socket closed before complete frame")
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def write_frame(sock: socket.socket, frame: Frame, *, max_bytes: int = MAX_FRAME_BYTES) -> None:
    """Write one complete frame to an already-connected broker socket."""
    sock.sendall(encode_frame(frame, max_bytes=max_bytes))


def read_frame(sock: socket.socket, *, max_bytes: int = MAX_FRAME_BYTES) -> Frame:
    """Read one complete frame and reject oversized lengths before allocation."""
    prefix = _read_exact(sock, _LENGTH.size)
    (size,) = _LENGTH.unpack(prefix)
    if size == 0 or size > max_bytes:
        raise TransportError("frame length exceeds maximum size")
    return decode_frame(_read_exact(sock, size), max_bytes=max_bytes)


__all__ = [
    "MAX_FRAME_BYTES",
    "Frame",
    "TransportError",
    "decode_frame",
    "encode_frame",
    "read_frame",
    "write_frame",
]
