from __future__ import annotations

from pathlib import Path

import pytest

from testudo.runtime import firecracker
from testudo.runtime.broker import BrokerError
from testudo.runtime.transport import MAX_FRAME_BYTES, Frame, decode_frame, encode_frame


class FakeVsock:
    def __init__(self, incoming: bytes = b"", *, connect_error: OSError | None = None) -> None:
        self.incoming = bytearray(incoming)
        self.connect_error = connect_error
        self.sent: list[bytes] = []
        self.timeout: float | None = None
        self.address: str | None = None
        self.closed = False

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def connect(self, address: str) -> None:
        if self.connect_error is not None:
            raise self.connect_error
        self.address = address

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


class CloseFailingVsock(FakeVsock):
    def close(self) -> None:
        self.closed = True
        raise OSError("close failed")


def _config(tmp_path: Path) -> firecracker.FirecrackerConfig:
    binary = tmp_path / "firecracker"
    kernel = tmp_path / "vmlinux"
    rootfs = tmp_path / "rootfs.ext4"
    for path in (binary, kernel, rootfs):
        path.write_bytes(b"fixture")
    binary.chmod(0o755)
    return firecracker.FirecrackerConfig(
        binary=binary,
        kernel_image=kernel,
        rootfs=rootfs,
        api_socket=tmp_path / "api.sock",
        vsock_socket=tmp_path / "vsock.sock",
    )


def _ready() -> bytes:
    return encode_frame(
        Frame(
            sequence=0,
            run_id="run-1",
            token_id="token-1",
            nonce="nonce-1",
            kind="ready",
            payload={"protocol": "testudo.vsock.frame.v1"},
        )
    )


def test_connector_selects_guest_port_and_returns_connected_socket() -> None:
    sock = FakeVsock(b"OK 1234\n")
    connector = firecracker.FirecrackerVsockConnector(
        Path("/run/testudo/vsock.sock"),
        guest_port=1234,
        timeout=2.5,
        socket_factory=lambda *_args: sock,
    )

    assert connector.connect() is sock
    assert sock.address == "/run/testudo/vsock.sock"
    assert sock.timeout == 2.5
    assert sock.sent == [b"CONNECT 1234\n"]


def test_connector_rejects_acknowledgement_port_mismatch() -> None:
    sock = FakeVsock(b"OK 9999\n")
    connector = firecracker.FirecrackerVsockConnector(
        Path("/run/testudo/vsock.sock"),
        guest_port=1234,
        socket_factory=lambda *_args: sock,
    )

    with pytest.raises(firecracker.FirecrackerError, match="does not match the requested"):
        connector.connect()
    assert sock.closed


def test_connector_closes_and_preserves_connection_failure() -> None:
    sock = FakeVsock(connect_error=OSError("not ready"))
    connector = firecracker.FirecrackerVsockConnector(
        Path("/run/testudo/vsock.sock"), socket_factory=lambda *_args: sock
    )

    with pytest.raises(firecracker.FirecrackerError, match="unable to connect"):
        connector.connect()
    assert sock.closed


def test_connector_rejects_invalid_ack_and_closes_socket() -> None:
    sock = FakeVsock(b"INVALID\\n")
    connector = firecracker.FirecrackerVsockConnector(
        Path("/run/testudo/vsock.sock"), socket_factory=lambda *_args: sock
    )

    with pytest.raises(firecracker.FirecrackerError, match="acknowledgement"):
        connector.connect()
    assert sock.closed


def test_connector_rejects_invalid_port_timeout_and_path() -> None:
    with pytest.raises(firecracker.FirecrackerError, match="guest vsock port"):
        firecracker.FirecrackerVsockConnector(Path("sock"), guest_port=0)
    with pytest.raises(firecracker.FirecrackerError, match="timeout"):
        firecracker.FirecrackerVsockConnector(Path("sock"), timeout=0)
    with pytest.raises(firecracker.FirecrackerError, match="too long"):
        firecracker.FirecrackerVsockConnector(Path("x" * 104))


def test_open_broker_session_connects_and_completes_guest_bootstrap(tmp_path: Path) -> None:
    sock = FakeVsock(b"OK 4321\n" + _ready())
    connector = firecracker.FirecrackerVsockConnector(
        Path("v.sock"), guest_port=4321, socket_factory=lambda *_args: sock
    )

    session = firecracker.open_broker_session(
        _config(tmp_path),
        run_id="run-1",
        token_id="token-1",
        nonce="nonce-1",
        contract={"image_digest": "sha256:image"},
        connector=connector,
    )

    assert session.state == "ready"
    assert sock.sent[0] == b"CONNECT 4321\n"
    bootstrap = decode_frame(sock.sent[1][4:])
    assert bootstrap.kind == "bootstrap"
    assert bootstrap.payload["run_id"] == "run-1"
    assert bootstrap.payload["token_id"] == "token-1"
    assert bootstrap.payload["nonce"] == "nonce-1"
    session.close()


def test_open_broker_session_rejects_mismatched_contract_before_connect(tmp_path: Path) -> None:
    calls: list[str] = []
    connector = firecracker.FirecrackerVsockConnector(
        Path("v.sock"),
        socket_factory=lambda *_args: calls.append("connect") or FakeVsock(),
    )

    with pytest.raises(firecracker.FirecrackerError, match="run_id"):
        firecracker.open_broker_session(
            _config(tmp_path),
            run_id="run-1",
            token_id="token-1",
            nonce="nonce-1",
            contract={"run_id": "different"},
            connector=connector,
        )
    assert calls == []


def test_open_broker_session_closes_on_bootstrap_failure_and_notes_close_error(
    tmp_path: Path,
) -> None:
    failure = encode_frame(
        Frame(
            sequence=0,
            run_id="run-1",
            token_id="token-1",
            nonce="nonce-1",
            kind="error",
            payload={"error": "guest rejected"},
        )
    )
    sock = CloseFailingVsock(b"OK 10000\n" + failure)
    connector = firecracker.FirecrackerVsockConnector(
        Path("v.sock"), socket_factory=lambda *_args: sock
    )

    with pytest.raises(BrokerError, match="cannot receive error") as caught:
        firecracker.open_broker_session(
            _config(tmp_path),
            run_id="run-1",
            token_id="token-1",
            nonce="nonce-1",
            contract={},
            connector=connector,
        )
    assert sock.closed
    assert any("close failed" in note for note in caught.value.__notes__)

    def test_open_broker_session_closes_if_session_admission_fails(tmp_path: Path) -> None:
        sock = FakeVsock(_ready())
        connector = firecracker.FirecrackerVsockConnector(
            Path("v.sock"), socket_factory=lambda *_args: sock
        )

        with pytest.raises(BrokerError, match="max_bytes"):
            firecracker.open_broker_session(
                _config(tmp_path),
                run_id="run-1",
                token_id="token-1",
                nonce="nonce-1",
                contract={},
                max_bytes=MAX_FRAME_BYTES + 1,
                connector=connector,
            )
        assert sock.closed
