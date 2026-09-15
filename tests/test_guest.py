from __future__ import annotations

import pytest

from testudo.runtime.broker import BrokerSession
from testudo.runtime.guest import GuestError, GuestSession
from testudo.runtime.transport import Frame, encode_frame


class DuplexEndpoint:
    def __init__(self) -> None:
        self.incoming = bytearray()
        self.peer: DuplexEndpoint | None = None
        self.closed = False

    def sendall(self, data: bytes) -> None:
        assert self.peer is not None
        self.peer.incoming.extend(data)

    def recv(self, size: int) -> bytes:
        if not self.incoming:
            return b""
        chunk = bytes(self.incoming[:size])
        del self.incoming[:size]
        return chunk

    def close(self) -> None:
        self.closed = True


def pair() -> tuple[DuplexEndpoint, DuplexEndpoint]:
    left = DuplexEndpoint()
    right = DuplexEndpoint()
    left.peer = right
    right.peer = left
    return left, right


def _sessions() -> tuple[BrokerSession, GuestSession]:
    host_sock, guest_sock = pair()
    return (
        BrokerSession(host_sock, run_id="run-1", token_id="token-1", nonce="nonce-1"),
        GuestSession(guest_sock, run_id="run-1", token_id="token-1", nonce="nonce-1"),
    )


def _bootstrap(host: BrokerSession, guest: GuestSession) -> None:
    host.send(
        "bootstrap",
        {
            "run_id": "run-1",
            "token_id": "token-1",
            "nonce": "nonce-1",
            "image_digest": "sha256:image",
        },
    )
    assert guest.bootstrap().kind == "ready"
    assert host.receive().kind == "ready"


def test_guest_bootstrap_run_stream_and_result_interoperate_with_host() -> None:
    host, guest = _sessions()
    _bootstrap(host, guest)

    host.run({"name": "workflow"}, {"input": "value"})
    workflow, inputs = guest.receive_run()
    assert workflow == {"name": "workflow"}
    assert inputs == {"input": "value"}
    guest.send_stdout("hello")
    guest.send_receipt({"artifact_hash": "a" * 64})
    guest.send_result({"exit_status": 0})

    assert host.receive().kind == "stdout"
    assert host.receive().kind == "receipt"
    assert host.receive().kind == "result"
    assert host.state == "terminal"
    assert guest.state == "terminal"


def test_guest_bootstrap_requires_all_context_fields() -> None:
    host, guest = _sessions()
    host.send("bootstrap", {"run_id": "run-1", "token_id": "token-1"})
    with pytest.raises(GuestError, match="nonce"):
        guest.bootstrap()
    assert guest.state == "terminal"


def test_guest_rejects_context_and_sequence_mismatch() -> None:
    _host_sock, guest_sock = pair()
    guest = GuestSession(guest_sock, run_id="run-1", token_id="token-1", nonce="nonce-1")
    assert guest_sock.peer is not None
    guest_sock.peer.sendall(
        encode_frame(
            Frame(
                sequence=1,
                run_id="run-1",
                token_id="token-1",
                nonce="nonce-1",
                kind="bootstrap",
                payload={},
            )
        )
    )
    with pytest.raises(GuestError, match="sequence"):
        guest.receive_command()
    assert guest.state == "terminal"

    _host_sock, guest_sock = pair()
    guest = GuestSession(guest_sock, run_id="run-1", token_id="token-1", nonce="nonce-1")
    assert guest_sock.peer is not None
    guest_sock.peer.sendall(
        encode_frame(
            Frame(
                sequence=0,
                run_id="different",
                token_id="token-1",
                nonce="nonce-1",
                kind="bootstrap",
                payload={},
            )
        )
    )
    with pytest.raises(GuestError, match="identity"):
        guest.receive_command()
    assert guest.state == "terminal"


def test_guest_rejects_illegal_state_and_kind() -> None:
    _host_sock, guest_sock = pair()
    guest = GuestSession(guest_sock, run_id="run-1", token_id="token-1", nonce="nonce-1")
    with pytest.raises(GuestError, match="state"):
        guest.send_result({})

    assert guest_sock.peer is not None
    guest_sock.peer.sendall(
        encode_frame(
            Frame(
                sequence=0,
                run_id="run-1",
                token_id="token-1",
                nonce="nonce-1",
                kind="ready",
                payload={},
            )
        )
    )
    with pytest.raises(GuestError, match="not allowed"):
        guest.receive_command()


def test_guest_run_requires_maps_and_close_is_idempotent() -> None:
    host, guest = _sessions()
    host.send(
        "bootstrap",
        {"run_id": "run-1", "token_id": "token-1", "nonce": "nonce-1"},
    )
    guest.bootstrap()
    host.receive()
    host.send("run", {"workflow": "not-a-map", "inputs": {}})
    with pytest.raises(GuestError, match="workflow and inputs"):
        guest.receive_run()
    assert guest.state == "terminal"
    guest.close()
    guest.close()
    assert guest.state == "closed"
