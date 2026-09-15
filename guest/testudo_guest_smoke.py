#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Julen Gamboa <julen.gamboa@example.invalid>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Minimal Testudo guest entrypoint for the first Firecracker smoke.

This entrypoint deliberately executes no workflow code and opens no network
socket. It mounts only devtmpfs, listens on the admitted Firecracker guest
vsock port, validates the context-bound bootstrap/run frames, and returns one
hash-bound terminal receipt. It is a transport/containment smoke guest, not a
workflow runner.

The implementation is stdlib-only so it can be copied into an admitted Ubuntu
rootfs without installing Python packages. The CBOR codec implements exactly
the finite types used by the Testudo frame contract and rejects indefinite or
trailing data.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import struct
import subprocess
import sys
from collections.abc import Mapping
from typing import Any

MAX_FRAME_BYTES = 4 * 1024 * 1024
FRAME_SCHEMA = "testudo.vsock.frame.v1"
GUEST_RECEIPT_SCHEMA = "testudo.guest.receipt.v1"
GUEST_PORT = 10000
GUEST_MODE = "stdio"


class GuestSmokeError(RuntimeError):
    """A frame or guest bootstrap violates the smoke contract."""


def _cbor_head(major: int, value: int) -> bytes:
    if value < 0:
        raise GuestSmokeError("CBOR length/value cannot be negative")
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 1 << 8:
        return bytes([(major << 5) | 24, value])
    if value < 1 << 16:
        return bytes([(major << 5) | 25]) + struct.pack(">H", value)
    if value < 1 << 32:
        return bytes([(major << 5) | 26]) + struct.pack(">I", value)
    if value < 1 << 64:
        return bytes([(major << 5) | 27]) + struct.pack(">Q", value)
    raise GuestSmokeError("CBOR integer/length is too large")


def encode_cbor(value: Any) -> bytes:
    """Encode the finite canonical-CBOR value set used by Testudo frames."""
    if value is None:
        return b"\xf6"
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, int) and not isinstance(value, bool):
        return _cbor_head(0, value) if value >= 0 else _cbor_head(1, -1 - value)
    if isinstance(value, bytes):
        return _cbor_head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _cbor_head(3, len(encoded)) + encoded
    if isinstance(value, (list, tuple)):
        return _cbor_head(4, len(value)) + b"".join(encode_cbor(item) for item in value)
    if isinstance(value, Mapping):
        encoded_items = [(encode_cbor(key), encode_cbor(item)) for key, item in value.items()]
        encoded_items.sort(key=lambda item: item[0])
        return _cbor_head(5, len(encoded_items)) + b"".join(
            key + item for key, item in encoded_items
        )
    if isinstance(value, float):
        return b"\xfb" + struct.pack(">d", value)
    raise GuestSmokeError(f"unsupported CBOR value: {type(value).__name__}")


class _CborDecoder:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.offset = 0

    def take(self, size: int) -> bytes:
        end = self.offset + size
        if size < 0 or end > len(self.body):
            raise GuestSmokeError("CBOR value is truncated")
        value = self.body[self.offset : end]
        self.offset = end
        return value

    def uint(self, additional: int) -> int:
        if additional < 24:
            return additional
        if additional == 24:
            return self.take(1)[0]
        if additional == 25:
            return int(struct.unpack(">H", self.take(2))[0])
        if additional == 26:
            return int(struct.unpack(">I", self.take(4))[0])
        if additional == 27:
            return int(struct.unpack(">Q", self.take(8))[0])
        raise GuestSmokeError("indefinite or invalid CBOR length is forbidden")

    def value(self) -> Any:
        initial = self.take(1)[0]
        major, additional = initial >> 5, initial & 0x1F
        if major == 0:
            return self.uint(additional)
        if major == 1:
            return -1 - self.uint(additional)
        if major == 2:
            return self.take(self.uint(additional))
        if major == 3:
            try:
                return self.take(self.uint(additional)).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise GuestSmokeError("CBOR text is not valid UTF-8") from exc
        if major == 4:
            return [self.value() for _ in range(self.uint(additional))]
        if major == 5:
            result: dict[Any, Any] = {}
            for _ in range(self.uint(additional)):
                key = self.value()
                if key in result:
                    raise GuestSmokeError("CBOR map contains duplicate keys")
                result[key] = self.value()
            return result
        if major == 7 and additional == 20:
            return False
        if major == 7 and additional == 21:
            return True
        if major == 7 and additional == 22:
            return None
        if major == 7 and additional == 27:
            return struct.unpack(">d", self.take(8))[0]
        raise GuestSmokeError("unsupported or indefinite CBOR value")


def decode_cbor(body: bytes) -> Any:
    """Decode one canonical-CBOR body and reject trailing bytes."""
    decoder = _CborDecoder(body)
    value = decoder.value()
    if decoder.offset != len(body):
        raise GuestSmokeError("trailing bytes after CBOR value")
    if encode_cbor(value) != body:
        raise GuestSmokeError("CBOR body is not canonical")
    return value


def _read_exact(sock: socket.socket, size: int) -> bytes:
    parts: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise GuestSmokeError("host socket closed before frame completed")
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def _read_frame(sock: socket.socket) -> dict[str, Any]:
    (size,) = struct.unpack(">I", _read_exact(sock, 4))
    if size == 0 or size > MAX_FRAME_BYTES:
        raise GuestSmokeError("host frame exceeds the bounded transport limit")
    value = decode_cbor(_read_exact(sock, size))
    if not isinstance(value, dict):
        raise GuestSmokeError("host frame must be a map")
    expected = {"schema", "sequence", "run_id", "token_id", "nonce", "kind", "payload"}
    if set(value) != expected or value.get("schema") != FRAME_SCHEMA:
        raise GuestSmokeError("host frame schema or keys are invalid")
    if not isinstance(value.get("payload"), dict):
        raise GuestSmokeError("host frame payload must be a map")
    return value


class StdioGuestSocket:
    """Borrowed stdin/stdout descriptors implementing the framed socket seam."""

    def __init__(self, read_fd: int, write_fd: int) -> None:
        self._read_fd = read_fd
        self._write_fd = write_fd

    def recv(self, size: int) -> bytes:
        return os.read(self._read_fd, size)

    def sendall(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(self._write_fd, view)
            if written <= 0:
                raise GuestSmokeError("stdio transport made no write progress")
            view = view[written:]

    def close(self) -> None:
        """Leave process-owned standard descriptors open."""


def _write_frame(
    sock: socket.socket,
    *,
    sequence: int,
    run_id: str,
    token_id: str,
    nonce: str,
    kind: str,
    payload: Mapping[str, Any],
) -> None:
    frame = {
        "schema": FRAME_SCHEMA,
        "sequence": sequence,
        "run_id": run_id,
        "token_id": token_id,
        "nonce": nonce,
        "kind": kind,
        "payload": dict(payload),
    }
    body = encode_cbor(frame)
    if len(body) > MAX_FRAME_BYTES:
        raise GuestSmokeError("guest frame exceeds the bounded transport limit")
    sock.sendall(struct.pack(">I", len(body)) + body)


def _require_identity(frame: Mapping[str, Any]) -> tuple[str, str, str]:
    values = tuple(frame.get(field) for field in ("run_id", "token_id", "nonce"))
    if not all(isinstance(value, str) and value for value in values):
        raise GuestSmokeError("host frame identity is required")
    return values  # type: ignore[return-value]


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def serve(sock: socket.socket) -> None:
    """Serve exactly one no-op smoke run over an already-connected socket."""
    bootstrap = _read_frame(sock)
    if bootstrap.get("sequence") != 0 or bootstrap.get("kind") != "bootstrap":
        raise GuestSmokeError("smoke guest expected bootstrap sequence zero")
    run_id, token_id, nonce = _require_identity(bootstrap)
    bootstrap_payload = bootstrap["payload"]
    for field, expected in (("run_id", run_id), ("token_id", token_id), ("nonce", nonce)):
        if bootstrap_payload.get(field) != expected:
            raise GuestSmokeError(f"bootstrap {field} does not match frame identity")

    _write_frame(
        sock,
        sequence=0,
        run_id=run_id,
        token_id=token_id,
        nonce=nonce,
        kind="ready",
        payload={"protocol": FRAME_SCHEMA},
    )

    command = _read_frame(sock)
    if command.get("sequence") != 1 or command.get("kind") != "run":
        raise GuestSmokeError("smoke guest expected one run command at sequence one")
    if tuple(command.get(field) for field in ("run_id", "token_id", "nonce")) != (
        run_id,
        token_id,
        nonce,
    ):
        raise GuestSmokeError("run identity does not match bootstrap")

    artifact_digest = bootstrap_payload.get("artifact_digest")
    if (
        not isinstance(artifact_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", artifact_digest) is None
    ):
        raise GuestSmokeError("bootstrap artifact_digest must be canonical SHA-256")
    containment = bootstrap_payload.get("containment")
    receipt_containment: dict[str, object] | None = None
    if containment is not None:
        if not isinstance(containment, dict):
            raise GuestSmokeError("bootstrap containment contract must be an object")
        taxonomy_sha256 = containment.get("taxonomy_sha256")
        monitor_schema = containment.get("monitor_schema")
        if (
            not isinstance(taxonomy_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", taxonomy_sha256) is None
        ):
            raise GuestSmokeError("bootstrap containment taxonomy digest is invalid")
        if not isinstance(monitor_schema, str) or not monitor_schema:
            raise GuestSmokeError("bootstrap containment monitor schema is invalid")
        receipt_containment = {**containment, "monitor_active": True}

    _write_frame(
        sock,
        sequence=1,
        run_id=run_id,
        token_id=token_id,
        nonce=nonce,
        kind="stdout",
        payload={"chunk": "testudo guest bootstrap accepted\n"},
    )
    result = {"exit_status": 0, "artifact_digest": artifact_digest}
    result_sha256 = hashlib.sha256(_canonical_json(result)).hexdigest()
    _write_frame(
        sock,
        sequence=2,
        run_id=run_id,
        token_id=token_id,
        nonce=nonce,
        kind="receipt",
        payload={
            "schema": GUEST_RECEIPT_SCHEMA,
            "run_id": run_id,
            "token_id": token_id,
            "nonce": nonce,
            "result_sha256": result_sha256,
            "artifact_digest": artifact_digest,
            **({"containment": receipt_containment} if receipt_containment is not None else {}),
        },
    )
    _write_frame(
        sock,
        sequence=3,
        run_id=run_id,
        token_id=token_id,
        nonce=nonce,
        kind="result",
        payload={**result, "result_sha256": result_sha256},
    )


def main() -> int:
    """Serve over explicit native stdio or Firecracker host vsock."""
    mode = os.environ.get("TESTUDO_GUEST_MODE")
    protocol = os.environ.get("TESTUDO_GUEST_PROTOCOL")
    if mode is not None:
        if mode != GUEST_MODE or protocol != FRAME_SCHEMA:
            raise GuestSmokeError("unsupported native guest mode or protocol")
        serve(StdioGuestSocket(sys.stdin.fileno(), sys.stdout.fileno()))  # type: ignore[arg-type]
        return 0
    if protocol is not None:
        raise GuestSmokeError("guest protocol requires explicit stdio mode")

    subprocess.run(
        ["/bin/mount", "-t", "devtmpfs", "devtmpfs", "/dev"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    family = getattr(socket, "AF_VSOCK", None)
    if family is None:
        raise GuestSmokeError("guest Python does not expose AF_VSOCK")
    listener = socket.socket(family, socket.SOCK_STREAM)
    connection: socket.socket | None = None
    try:
        listener.bind((getattr(socket, "VMADDR_CID_ANY", 0xFFFFFFFF), GUEST_PORT))
        listener.listen(1)
        connection, _address = listener.accept()
        serve(connection)
    finally:
        if connection is not None:
            connection.close()
        listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
