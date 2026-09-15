from __future__ import annotations

import struct

import pytest

from testudo.runtime.broker import BrokerError, BrokerSession
from testudo.runtime.transport import MAX_FRAME_BYTES, Frame, encode_frame


class FakeSocket:
    def __init__(self, incoming: bytes = b"") -> None:
        self.incoming = bytearray(incoming)
        self.sent: list[bytes] = []
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, size: int) -> bytes:
        if not self.incoming:
            return b""
        chunk = bytes(self.incoming[:size])
        del self.incoming[:size]
        return chunk

    def close(self) -> None:
        self.closed = True


def guest_frame(
    kind: str,
    *,
    sequence: int,
    run_id: str = "run-1",
    token_id: str = "token-1",
    nonce: str = "nonce-1",
    payload: dict[str, object] | None = None,
) -> bytes:
    return encode_frame(
        Frame(
            sequence=sequence,
            run_id=run_id,
            token_id=token_id,
            nonce=nonce,
            kind=kind,
            payload=payload or {},
        )
    )


def session(*incoming: bytes) -> tuple[BrokerSession, FakeSocket]:
    sock = FakeSocket(b"".join(incoming))
    return BrokerSession(sock, run_id="run-1", token_id="token-1", nonce="nonce-1"), sock


def test_bootstrap_run_and_terminal_result_bind_context_and_sequence() -> None:
    broker, sock = session(
        guest_frame("ready", sequence=0),
        guest_frame("result", sequence=1, payload={"exit_status": 0}),
    )

    ready = broker.bootstrap({"image": "sha256:image"})
    assert ready.kind == "ready"
    assert broker.state == "ready"
    request = broker.run({"workflow": "workflow.json"}, {"input": "value"})
    assert request.sequence == 1
    result = broker.receive()
    assert result.kind == "result"
    assert broker.state == "terminal"
    assert len(sock.sent) == 2


def test_stop_is_allowed_after_run_and_closes_protocol() -> None:
    broker, _sock = session(guest_frame("ready", sequence=0))
    broker.bootstrap({})
    broker.run({}, {})
    stop = broker.stop()
    assert stop.kind == "stop"
    assert broker.state == "stop_requested"


def test_run_requires_ready_and_unknown_host_kind_is_denied() -> None:
    broker, _sock = session()
    with pytest.raises(BrokerError, match="state"):
        broker.run({}, {})
    with pytest.raises(BrokerError, match="not allowed"):
        broker.send("result", {})


@pytest.mark.parametrize("field", ["run_id", "token_id", "nonce"])
def test_guest_context_mismatch_fails_closed(field: str) -> None:
    values = {"run_id": "run-1", "token_id": "token-1", "nonce": "nonce-1"}
    values[field] = "wrong"
    broker, _sock = session(
        guest_frame(
            "ready",
            sequence=0,
            run_id=values["run_id"],
            token_id=values["token_id"],
            nonce=values["nonce"],
        )
    )
    with pytest.raises(BrokerError, match="does not match"):
        broker.bootstrap({})
    assert broker.state == "terminal"


def test_guest_sequence_must_be_monotonic() -> None:
    broker, _sock = session(guest_frame("ready", sequence=1))
    with pytest.raises(BrokerError, match="sequence"):
        broker.bootstrap({})
    assert broker.state == "terminal"


def test_illegal_guest_kind_and_state_are_rejected() -> None:
    broker, _sock = session(guest_frame("run", sequence=0))
    with pytest.raises(BrokerError, match="not allowed"):
        broker.bootstrap({})

    broker, _sock = session(
        guest_frame("ready", sequence=0),
        guest_frame("stdout", sequence=1),
    )
    broker.bootstrap({})
    with pytest.raises(BrokerError, match="state"):
        broker.receive()


def test_oversized_frame_is_rejected_before_decode() -> None:
    sock = FakeSocket(struct.pack(">I", MAX_FRAME_BYTES + 1))
    broker = BrokerSession(sock, run_id="run-1", token_id="token-1", nonce="nonce-1")
    with pytest.raises(BrokerError, match="maximum size"):
        broker.receive()
    assert broker.state == "terminal"


def test_close_is_idempotent() -> None:
    broker, sock = session()
    broker.close()
    broker.close()
    assert sock.closed
    assert broker.state == "closed"
    with pytest.raises(BrokerError, match="closed"):
        broker.send("bootstrap", {})
