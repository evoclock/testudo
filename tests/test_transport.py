# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for framed canonical-CBOR broker transport."""

from __future__ import annotations

import socket
import struct

import pytest

from testudo.runtime.transport import (
    Frame,
    TransportError,
    decode_frame,
    encode_frame,
    read_frame,
    write_frame,
)


def frame() -> Frame:
    return Frame(
        sequence=7,
        run_id="run-1",
        token_id="token-1",
        nonce="nonce-1",
        kind="export.chunk",
        payload={"path": "result.txt", "bytes": b"accepted"},
    )


def test_canonical_encoding_is_stable_and_round_trips() -> None:
    encoded = encode_frame(frame())
    decoded = decode_frame(encoded[4:])

    assert decoded == frame()
    assert encoded == encode_frame(
        Frame(
            sequence=7,
            run_id="run-1",
            token_id="token-1",
            nonce="nonce-1",
            kind="export.chunk",
            payload={"bytes": b"accepted", "path": "result.txt"},
        )
    )


def test_socket_helpers_handle_complete_frame() -> None:
    left, right = socket.socketpair()
    try:
        write_frame(left, frame())
        assert read_frame(right) == frame()
    finally:
        left.close()
        right.close()


def test_decode_rejects_unknown_keys_and_trailing_bytes() -> None:
    encoded = encode_frame(frame())
    with pytest.raises(TransportError, match="trailing"):
        decode_frame(encoded[4:] + b"junk")

    value = frame().to_mapping()
    value["unexpected"] = True
    import cbor2

    with pytest.raises(TransportError, match="keys"):
        decode_frame(cbor2.dumps(value, canonical=True))


def test_read_rejects_oversized_length_before_body_read() -> None:
    left, right = socket.socketpair()
    try:
        left.sendall(struct.pack(">I", 1024))
        with pytest.raises(TransportError, match="maximum"):
            read_frame(right, max_bytes=32)
    finally:
        left.close()
        right.close()


def test_frame_validates_binding_fields() -> None:
    with pytest.raises(TransportError, match="sequence"):
        Frame(sequence=-1, run_id="run", token_id="token", nonce="n", kind="k", payload={})
    with pytest.raises(TransportError, match="run_id"):
        Frame(sequence=0, run_id="", token_id="token", nonce="n", kind="k", payload={})
