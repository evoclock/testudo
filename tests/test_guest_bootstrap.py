from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import threading
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import guest.testudo_guest_bootstrap as bootstrap
from guest.testudo_guest_bootstrap import StdioGuestSocket, serve
from testudo.runtime.broker import BrokerSession
from testudo.runtime.containment import containment_contract, taxonomy_sha256

ARTIFACT_DIGEST = "a" * 64


def _session(sock: socket.socket) -> BrokerSession:
    return BrokerSession(sock, run_id="run-1", token_id="token-1", nonce="nonce-1")


def _bootstrap_contract(*, artifact_digest: str | None = ARTIFACT_DIGEST) -> dict[str, Any]:
    contract: dict[str, Any] = {
        "run_id": "run-1",
        "token_id": "token-1",
        "nonce": "nonce-1",
        "image_digest": "sha256:image",
        "guest_paths": {"workspace": "/runs", "inputs": "/inputs"},
    }
    if artifact_digest is not None:
        contract["artifact_digest"] = artifact_digest
    return contract


def _serve_in_thread(
    guest: socket.socket,
) -> tuple[threading.Thread, list[BaseException]]:
    failures: list[BaseException] = []

    def run() -> None:
        try:
            serve(guest)
        except BaseException as exc:  # pragma: no cover - assertion below reports it
            failures.append(exc)
        finally:
            guest.close()

    thread = threading.Thread(target=run)
    thread.start()
    return thread, failures


def test_guest_runs_workflow_executor_and_emits_hash_bound_receipt() -> None:
    host_sock, guest_sock = socket.socketpair()
    host = _session(host_sock)
    thread, failures = _serve_in_thread(guest_sock)
    try:
        host.bootstrap(_bootstrap_contract())
        host.run(
            {
                "name": "guest-demo",
                "steps": [{"id": "echo", "uses": "noop", "with": {"value": "${inputs.value}"}}],
            },
            {"value": "hello"},
        )
        stdout = host.receive()
        receipt = host.receive()
        result = host.receive()
    finally:
        host.close()
        thread.join(timeout=2)

    assert failures == []
    assert not thread.is_alive()
    assert stdout.kind == "stdout"
    rendered = json.loads(stdout.payload["chunk"])
    assert rendered["steps"]["echo"]["output"] == {"echoed": {"value": "hello"}}
    assert receipt.kind == "receipt"
    assert receipt.payload["artifact_digest"] == ARTIFACT_DIGEST
    assert result.kind == "result"

    result_without_hash = {
        key: value for key, value in result.payload.items() if key != "result_sha256"
    }
    expected_hash = hashlib.sha256(
        json.dumps(result_without_hash, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert result.payload["result_sha256"] == expected_hash
    assert receipt.payload["result_sha256"] == expected_hash


def test_guest_requires_active_matching_containment_monitor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = _bootstrap_contract()
    contract["containment"] = containment_contract()

    host_sock, guest_sock = socket.socketpair()
    host = _session(host_sock)
    thread, failures = _serve_in_thread(guest_sock)
    try:
        host.bootstrap(contract)
        host.run({"name": "guest-demo", "steps": [{"id": "echo", "uses": "noop"}]}, {})
        assert "not active" in host.receive().payload["chunk"]
        assert host.receive().kind == "error"
    finally:
        host.close()
        thread.join(timeout=2)
    assert failures == []

    monkeypatch.setenv("TESTUDO_CONTAINMENT_ACTIVE", taxonomy_sha256())
    host_sock, guest_sock = socket.socketpair()
    host = _session(host_sock)
    thread, failures = _serve_in_thread(guest_sock)
    try:
        host.bootstrap(contract)
        host.run({"name": "guest-demo", "steps": [{"id": "echo", "uses": "noop"}]}, {})
        assert host.receive().kind == "stdout"
        receipt = host.receive()
        assert receipt.payload["containment"]["monitor_active"] is True
        assert host.receive().kind == "result"
    finally:
        host.close()
        thread.join(timeout=2)
    assert failures == []


def test_guest_rejects_unbound_artifact_before_result() -> None:
    host_sock, guest_sock = socket.socketpair()
    host = _session(host_sock)
    thread, failures = _serve_in_thread(guest_sock)
    try:
        host.bootstrap(_bootstrap_contract(artifact_digest=None))
        host.run(
            {"name": "guest-demo", "steps": [{"id": "echo", "uses": "noop"}]},
            {},
        )
        stderr = host.receive()
        error = host.receive()
    finally:
        host.close()
        thread.join(timeout=2)

    assert failures == []
    assert not thread.is_alive()
    assert stderr.kind == "stderr"
    assert "artifact_digest" in stderr.payload["chunk"]
    assert error.kind == "error"
    assert "artifact_digest" in error.payload["error"]


@pytest.mark.parametrize("bad_digest", ["", "sha256:image", "A" * 64])
def test_guest_rejects_noncanonical_artifact_digest(bad_digest: str) -> None:
    host_sock, guest_sock = socket.socketpair()
    host = _session(host_sock)
    thread, failures = _serve_in_thread(guest_sock)
    try:
        host.bootstrap(_bootstrap_contract(artifact_digest=bad_digest))
        host.run(
            {"name": "guest-demo", "steps": [{"id": "echo", "uses": "noop"}]},
            {},
        )
        assert host.receive().kind == "stderr"
        assert host.receive().kind == "error"
    finally:
        host.close()
        thread.join(timeout=2)

    assert failures == []
    assert not thread.is_alive()


def test_guest_bootstrap_runs_over_explicit_stdio_pipes() -> None:
    host_to_guest_read, host_to_guest_write = os.pipe()
    guest_to_host_read, guest_to_host_write = os.pipe()
    guest = StdioGuestSocket(host_to_guest_read, guest_to_host_write)
    failures: list[BaseException] = []

    def run() -> None:
        try:
            serve(guest)
        except BaseException as exc:  # pragma: no cover - assertion below reports it
            failures.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    try:
        # The host transport uses the opposite ends of the two pipes.
        host = BrokerSession(
            StdioGuestSocket(guest_to_host_read, host_to_guest_write),
            run_id="run-1",
            token_id="token-1",
            nonce="nonce-1",
        )
        host.bootstrap(_bootstrap_contract())
        host.run(
            {"name": "guest-demo", "steps": [{"id": "echo", "uses": "noop"}]},
            {},
        )
        assert host.receive().kind == "stdout"
        assert host.receive().kind == "receipt"
        assert host.receive().kind == "result"
    finally:
        host.close()
        for fd in (
            host_to_guest_read,
            host_to_guest_write,
            guest_to_host_read,
            guest_to_host_write,
        ):
            with suppress(OSError):
                os.close(fd)
        thread.join(timeout=2)

    assert failures == []
    assert not thread.is_alive()


def test_stdio_main_requires_the_exact_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TESTUDO_GUEST_MODE", "stdio")
    monkeypatch.delenv("TESTUDO_GUEST_PROTOCOL", raising=False)
    with pytest.raises(bootstrap.GuestBootstrapError, match="GUEST_PROTOCOL"):
        bootstrap.main()

    monkeypatch.setenv("TESTUDO_GUEST_PROTOCOL", "wrong.protocol")
    with pytest.raises(bootstrap.GuestBootstrapError, match="GUEST_PROTOCOL"):
        bootstrap.main()


def test_stdio_main_dispatches_only_the_expected_protocol(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    served: list[object] = []
    monkeypatch.setenv("TESTUDO_GUEST_MODE", "stdio")
    monkeypatch.setenv("TESTUDO_GUEST_PROTOCOL", bootstrap.STDIO_GUEST_PROTOCOL)
    monkeypatch.setattr(bootstrap, "serve", served.append)
    monkeypatch.setattr(bootstrap.sys, "stdin", SimpleNamespace(fileno=lambda: 0))
    monkeypatch.setattr(bootstrap.sys, "stdout", SimpleNamespace(fileno=lambda: 1))

    assert bootstrap.main() == 0
    assert len(served) == 1
    assert isinstance(served[0], StdioGuestSocket)


def test_protocol_without_explicit_stdio_mode_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TESTUDO_GUEST_MODE", raising=False)
    monkeypatch.setenv("TESTUDO_GUEST_PROTOCOL", bootstrap.STDIO_GUEST_PROTOCOL)
    with pytest.raises(bootstrap.GuestBootstrapError, match="requires explicit stdio"):
        bootstrap.main()


def test_vsock_main_listens_and_serves_one_accepted_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The host transport dials the guest, so vsock mode must LISTEN on 10000.

    The listener socket is a mock created for AF_INET; this proves the bind /
    listen / accept / close sequencing of ``main``, not real AF_VSOCK kernel
    behaviour.  ``VMADDR_CID_ANY`` is patched explicitly so the bind address
    is asserted even on hosts that already expose a real vsock constant.
    """
    served: list[object] = []
    calls: list[tuple[str, tuple[object, ...]]] = []

    class FakeConnection:
        def close(self) -> None:
            calls.append(("connection-close", ()))

    connection = FakeConnection()

    class FakeSocket:
        def bind(self, address: tuple[object, ...]) -> None:
            calls.append(("bind", address))

        def listen(self, backlog: int) -> None:
            calls.append(("listen", (backlog,)))

        def accept(self) -> tuple[object, tuple[object, ...]]:
            calls.append(("accept", ()))
            return connection, (1234, 10000)

        def close(self) -> None:
            calls.append(("listener-close", ()))

    monkeypatch.delenv("TESTUDO_GUEST_MODE", raising=False)
    monkeypatch.delenv("TESTUDO_GUEST_PROTOCOL", raising=False)
    monkeypatch.setattr(bootstrap.socket, "AF_VSOCK", socket.AF_INET, raising=False)
    monkeypatch.setattr(bootstrap.socket, "VMADDR_CID_ANY", 0xFFFFFFFF, raising=False)
    monkeypatch.setattr(bootstrap.socket, "socket", lambda *a, **k: FakeSocket())
    monkeypatch.setattr(bootstrap, "serve", served.append)

    assert bootstrap.main() == 0
    # Full call order: bind to the any-CID/port pair, listen, accept exactly
    # one host connection, then close the accepted connection first and the
    # listener second.
    assert calls == [
        ("bind", (0xFFFFFFFF, bootstrap.GUEST_PORT)),
        ("listen", (1,)),
        ("accept", ()),
        ("connection-close", ()),
        ("listener-close", ()),
    ]
    assert served == [connection]


def test_vsock_main_fails_closed_on_accept_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An accept failure must close the listener, not leave it bound."""
    calls: list[str] = []

    class FakeSocket:
        def bind(self, address: tuple[object, ...]) -> None:
            pass

        def listen(self, backlog: int) -> None:
            pass

        def accept(self) -> tuple[socket.socket, tuple[object, ...]]:
            raise OSError("vsock listener reset")

        def close(self) -> None:
            calls.append("close")

    monkeypatch.delenv("TESTUDO_GUEST_MODE", raising=False)
    monkeypatch.delenv("TESTUDO_GUEST_PROTOCOL", raising=False)
    monkeypatch.setattr(bootstrap.socket, "AF_VSOCK", socket.AF_INET, raising=False)
    monkeypatch.setattr(bootstrap.socket, "VMADDR_CID_ANY", 0xFFFFFFFF, raising=False)
    monkeypatch.setattr(bootstrap.socket, "socket", lambda *a, **k: FakeSocket())
    monkeypatch.setattr(bootstrap, "serve", lambda sock: pytest.fail("must not serve"))

    with pytest.raises(bootstrap.GuestBootstrapError, match="vsock listener failed"):
        bootstrap.main()
    assert calls == ["close"]


def test_guest_binds_writable_allowlist_to_the_declared_contract_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guest.testudo_guest_bootstrap import GuestBootstrapError, _bind_writable_paths

    monkeypatch.delenv("TESTUDO_GUEST_WORKSPACE", raising=False)
    monkeypatch.delenv("TESTUDO_GUEST_WRITABLE_PATHS", raising=False)
    _bind_writable_paths({"guest_paths": {"workspace": "/runs/work", "inputs": "/inputs"}})
    import os

    assert os.environ["TESTUDO_GUEST_WORKSPACE"] == "/runs/work"
    assert os.environ["TESTUDO_GUEST_WRITABLE_PATHS"] == "/runs/work /tmp/session"
    # The fallback contract form (native container) is accepted too.
    _bind_writable_paths({"workspace": "/runs"})
    assert os.environ["TESTUDO_GUEST_WORKSPACE"] == "/runs"
    # A contract without a declared workspace fails closed: the guest must
    # never invent its own writable allowlist.
    monkeypatch.delenv("TESTUDO_GUEST_WORKSPACE", raising=False)
    with pytest.raises(GuestBootstrapError, match="workspace guest path"):
        _bind_writable_paths({"run_id": "run-1"})


def test_guest_writes_inside_declared_paths_do_not_trip_the_watcher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:

    monitor = Path(__file__).resolve().parents[1] / "guest" / "testudo_containment_monitor.sh"
    counter = iter(range(100))

    def detect(path: str, *, fresh: bool = False) -> dict[str, object]:
        target = tmp_path / f"state-{next(counter)}" if fresh else tmp_path / "run-1"
        result = subprocess.run(
            [str(monitor), "fs-detect", str(target), path],
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
            env={
                "PATH": "/usr/bin:/bin",
                "TESTUDO_GUEST_WORKSPACE": "/runs",
                "TESTUDO_GUEST_WRITABLE_PATHS": "/runs /tmp/session",
            },
        )
        assert result.returncode == 0
        value: dict[str, object] = json.loads(result.stdout)
        return value

    # Workflow-required workspace and exchange writes are sanctioned.
    assert detect("/runs")["decision"] == "allow"
    assert detect("/runs/exchange/output.txt")["decision"] == "allow"
    assert detect("/tmp/session/scratch")["decision"] == "allow"
    # The allowlist is prefix-exact: a sibling prefix is not writable.
    assert detect("/runsevil")["decision"] == "deny"
    # Writes outside the declared writable paths still trip deny-by-default;
    # each deny uses a fresh state dir because HIGH denials freeze a session.
    assert detect("/etc/passwd", fresh=True)["decision"] == "deny"
    assert detect("/var/cache/pip", fresh=True)["decision"] == "deny"
