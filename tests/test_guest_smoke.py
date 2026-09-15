# SPDX-FileCopyrightText: 2026 Julen Gamboa <julen.gamboa@example.invalid>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Fake-duplex tests for the standalone Firecracker guest smoke entrypoint."""

from __future__ import annotations

import hashlib
import json
import socket
import threading
from types import SimpleNamespace
from typing import Any

import pytest

import guest.testudo_guest_smoke as guest_smoke
from guest.testudo_guest_smoke import (
    GuestSmokeError,
    StdioGuestSocket,
    decode_cbor,
    encode_cbor,
    serve,
)
from testudo.runtime.transport import Frame, read_frame, write_frame


def _frame(*, sequence: int, kind: str, payload: dict[str, Any]) -> Frame:
    return Frame(
        sequence=sequence,
        run_id="run-1",
        token_id="token-1",
        nonce="nonce-1",
        kind=kind,
        payload=payload,
    )


def test_guest_smoke_receipt_carries_validated_containment_block() -> None:
    """A containment-bearing bootstrap contract must reach the receipt intact."""
    host, guest = socket.socketpair()
    failures: list[BaseException] = []

    def run_guest() -> None:
        try:
            serve(guest)
        except BaseException as exc:  # pragma: no cover - assertion below reports it
            failures.append(exc)
        finally:
            guest.close()

    thread = threading.Thread(target=run_guest)
    thread.start()
    try:
        write_frame(
            host,
            _frame(
                sequence=0,
                kind="bootstrap",
                payload={
                    "run_id": "run-1",
                    "token_id": "token-1",
                    "nonce": "nonce-1",
                    "artifact_digest": "a" * 64,
                    "containment": {
                        "monitor_schema": "guest-containment-taxonomy.v1",
                        "taxonomy_sha256": "b" * 64,
                    },
                },
            ),
        )
        ready = read_frame(host)
        assert ready.kind == "ready"

        write_frame(
            host,
            _frame(sequence=1, kind="run", payload={"workflow": {}, "inputs": {}}),
        )
        stdout = read_frame(host)
        assert stdout.kind == "stdout"
        receipt = read_frame(host)
        assert receipt.kind == "receipt"
        result = read_frame(host)
        assert result.kind == "result"
        containment = receipt.payload.get("containment")
        assert isinstance(containment, dict)
        assert containment["taxonomy_sha256"] == "b" * 64
        assert containment["monitor_schema"] == "guest-containment-taxonomy.v1"
        assert containment["monitor_active"] is True
    finally:
        host.close()
        thread.join(timeout=5)
    assert failures == []


def test_guest_smoke_completes_context_bound_noop_exchange() -> None:
    host, guest = socket.socketpair()
    failures: list[BaseException] = []

    def run_guest() -> None:
        try:
            serve(guest)
        except BaseException as exc:  # pragma: no cover - assertion below reports it
            failures.append(exc)
        finally:
            guest.close()

    thread = threading.Thread(target=run_guest)
    thread.start()
    try:
        write_frame(
            host,
            _frame(
                sequence=0,
                kind="bootstrap",
                payload={
                    "run_id": "run-1",
                    "token_id": "token-1",
                    "nonce": "nonce-1",
                    "artifact_digest": "a" * 64,
                },
            ),
        )
        ready = read_frame(host)
        assert ready.kind == "ready"
        assert ready.sequence == 0
        assert ready.payload == {"protocol": "testudo.vsock.frame.v1"}

        write_frame(
            host,
            _frame(sequence=1, kind="run", payload={"workflow": {}, "inputs": {}}),
        )
        stdout = read_frame(host)
        receipt = read_frame(host)
        result = read_frame(host)
    finally:
        host.close()
        thread.join(timeout=2)

    assert failures == []
    assert not thread.is_alive()
    assert stdout.kind == "stdout"
    assert stdout.sequence == 1
    assert stdout.payload == {"chunk": "testudo guest bootstrap accepted\n"}
    assert receipt.kind == "receipt"
    assert receipt.sequence == 2
    assert result.kind == "result"
    assert result.sequence == 3

    result_without_hash = {
        "exit_status": result.payload["exit_status"],
        "artifact_digest": result.payload["artifact_digest"],
    }
    expected_hash = hashlib.sha256(
        json.dumps(result_without_hash, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert result.payload["result_sha256"] == expected_hash
    assert receipt.payload["result_sha256"] == expected_hash
    assert receipt.payload["artifact_digest"] == result.payload["artifact_digest"]


def test_guest_smoke_rejects_wrong_first_command() -> None:
    host, guest = socket.socketpair()
    failures: list[BaseException] = []

    def run_guest() -> None:
        try:
            serve(guest)
        except BaseException as exc:
            failures.append(exc)
        finally:
            guest.close()

    thread = threading.Thread(target=run_guest)
    thread.start()
    try:
        write_frame(
            host,
            _frame(
                sequence=0,
                kind="run",
                payload={"run_id": "run-1", "token_id": "token-1", "nonce": "nonce-1"},
            ),
        )
        thread.join(timeout=2)
    finally:
        host.close()
        thread.join(timeout=2)

    assert not thread.is_alive()
    assert len(failures) == 1
    assert isinstance(failures[0], GuestSmokeError)


def test_guest_smoke_main_listens_for_firecracker_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []

    class Connection:
        def close(self) -> None:
            events.append("connection-close")

    class Listener:
        def bind(self, address: object) -> None:
            events.append(("bind", address))

        def listen(self, backlog: int) -> None:
            events.append(("listen", backlog))

        def accept(self) -> tuple[Connection, object]:
            events.append("accept")
            return Connection(), (2, guest_smoke.GUEST_PORT)

        def close(self) -> None:
            events.append("listener-close")

    listener = Listener()
    monkeypatch.delenv("TESTUDO_GUEST_MODE", raising=False)
    monkeypatch.delenv("TESTUDO_GUEST_PROTOCOL", raising=False)
    monkeypatch.setattr(guest_smoke.subprocess, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(guest_smoke.socket, "AF_VSOCK", 40, raising=False)
    monkeypatch.setattr(guest_smoke.socket, "VMADDR_CID_ANY", 0xFFFFFFFF, raising=False)
    monkeypatch.setattr(guest_smoke.socket, "socket", lambda *args: listener)
    monkeypatch.setattr(guest_smoke, "serve", lambda connection: events.append(connection))

    assert guest_smoke.main() == 0
    assert events[0] == ("bind", (0xFFFFFFFF, guest_smoke.GUEST_PORT))
    assert events[1:3] == [("listen", 1), "accept"]
    assert isinstance(events[3], Connection)
    assert events[4:] == ["connection-close", "listener-close"]


def test_guest_smoke_main_dispatches_explicit_stdio(monkeypatch: pytest.MonkeyPatch) -> None:
    served: list[object] = []
    monkeypatch.setenv("TESTUDO_GUEST_MODE", "stdio")
    monkeypatch.setenv("TESTUDO_GUEST_PROTOCOL", guest_smoke.FRAME_SCHEMA)
    monkeypatch.setattr(guest_smoke, "serve", served.append)
    monkeypatch.setattr(guest_smoke.sys, "stdin", SimpleNamespace(fileno=lambda: 0))
    monkeypatch.setattr(guest_smoke.sys, "stdout", SimpleNamespace(fileno=lambda: 1))

    assert guest_smoke.main() == 0
    assert len(served) == 1
    assert isinstance(served[0], StdioGuestSocket)


def test_guest_smoke_main_rejects_wrong_stdio_protocol(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TESTUDO_GUEST_MODE", "stdio")
    monkeypatch.setenv("TESTUDO_GUEST_PROTOCOL", "wrong")
    with pytest.raises(GuestSmokeError, match="unsupported"):
        guest_smoke.main()


@pytest.mark.parametrize("value", [{"b": 1, "a": 2}, [1, "two", None], True, -7])
def test_guest_cbor_codec_is_canonical(value: Any) -> None:
    encoded = encode_cbor(value)
    assert decode_cbor(encoded) == value
