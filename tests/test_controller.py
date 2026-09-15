from __future__ import annotations

import hashlib
import json
import socket
import threading
from types import SimpleNamespace
from typing import Any

import pytest

from testudo.runtime.broker import BrokerSession
from testudo.runtime.capability import WorkerTerminated
from testudo.runtime.controller import HostController, HostControllerError
from testudo.runtime.docker import RunResult
from testudo.runtime.firecracker import FirecrackerOutput
from testudo.runtime.guest import GuestSession


def pair() -> tuple[socket.socket, socket.socket]:
    return socket.socketpair()


class FakeLifecycle:
    def __init__(self, *, status: int = 0, expire: bool = False) -> None:
        self.supervisor = SimpleNamespace(token=SimpleNamespace(token_id="token-1"))
        self.status = status
        self.expire = expire
        self.stop_calls: list[str] = []
        self.wait_calls = 0

    def check(self) -> None:
        if self.expire:
            raise WorkerTerminated("expired")

    def wait(self, *, timeout: float | None = None) -> int:
        del timeout
        self.wait_calls += 1
        return self.status

    def stop(self, reason: str = "operator_stop") -> None:
        self.stop_calls.append(reason)


class FakeAdapter:
    def __init__(self, broker: BrokerSession, lifecycle: FakeLifecycle) -> None:
        self.broker = broker
        self.lifecycle = lifecycle
        self.closed = 0

    def collect_output(self, *, timeout: float | None = 5.0) -> FirecrackerOutput:
        del timeout
        return FirecrackerOutput("host stdout", "host stderr")

    def close(self) -> None:
        self.closed += 1
        self.broker.close()


def _result_hash(payload: dict[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _contract() -> dict[str, str]:
    return {"run_id": "run-1", "token_id": "token-1", "nonce": "nonce-1"}


def _make_controller(
    *, status: int = 0, expire: bool = False, events: list[Any] | None = None
) -> tuple[HostController, GuestSession, FakeLifecycle, FakeAdapter]:
    host_sock, guest_sock = pair()
    broker = BrokerSession(host_sock, **_contract())
    guest = GuestSession(guest_sock, **_contract())
    lifecycle = FakeLifecycle(status=status, expire=expire)
    adapter = FakeAdapter(broker, lifecycle)
    controller = HostController(
        lambda **_kwargs: adapter,
        event_sink=events.append if events is not None else None,
    )
    return controller, guest, lifecycle, adapter


def _guest_success(guest: GuestSession, *, exit_status: int = 0) -> None:
    guest.bootstrap()
    guest.receive_run()
    guest.send_stdout("hello")
    guest.send_stderr("warning")
    result_without_hash: dict[str, object] = {"exit_status": exit_status, "output": "ok"}
    result_hash = _result_hash(result_without_hash)
    guest.send_receipt(
        {
            **_contract(),
            "schema": "testudo.guest.receipt.v1",
            "result_sha256": result_hash,
            "artifact_digest": "a" * 64,
        }
    )
    guest.send_result({**result_without_hash, "result_sha256": result_hash})


def _run(controller: HostController, guest: GuestSession, **kwargs: object) -> RunResult:
    guest_thread = threading.Thread(target=_guest_success, args=(guest,), kwargs=kwargs)
    guest_thread.start()
    result = controller.run(
        run_id="run-1",
        token_id="token-1",
        nonce="nonce-1",
        workflow={"name": "demo"},
        inputs={"value": "x"},
        contract={**_contract(), "image_digest": "sha256:image"},
    )
    guest_thread.join(timeout=2)
    assert not guest_thread.is_alive()
    return result


def test_controller_success_forwards_streams_and_hash_bound_receipts() -> None:
    events: list[Any] = []
    controller, guest, lifecycle, adapter = _make_controller(events=events)

    result = _run(controller, guest)

    assert result == RunResult(0, "hello", "warning", result.runtime_ms)
    assert lifecycle.stop_calls == []
    assert adapter.closed == 1
    assert [event.event for event in events] == [
        "transport",
        "transport",
        "transport",
        "stdout",
        "stderr",
        "output",
        "receipt",
        "supervisor",
        "revoke",
        "wipe",
    ]
    assert events[-2].details["reason"] == "worker_exit"
    assert events[-1].details["reason"] == "worker_exit"


def test_controller_preserves_nonzero_guest_result() -> None:
    controller, guest, lifecycle, _adapter = _make_controller(status=7)
    guest_thread = threading.Thread(target=_guest_success, args=(guest,), kwargs={"exit_status": 7})
    guest_thread.start()
    result = controller.run(
        run_id="run-1",
        token_id="token-1",
        nonce="nonce-1",
        workflow={},
        inputs={},
        contract=_contract(),
    )
    guest_thread.join(timeout=2)
    assert result.exit_status == 7
    assert lifecycle.stop_calls == []


def test_controller_rejects_context_before_launch() -> None:
    launched: list[str] = []
    controller = HostController(lambda **_kwargs: launched.append("launch"))
    with pytest.raises(HostControllerError, match="identity mismatch: nonce"):
        controller.run(
            run_id="run-1",
            token_id="token-1",
            nonce="nonce-1",
            workflow={},
            inputs={},
            contract={"run_id": "run-1", "token_id": "token-1", "nonce": "wrong"},
        )
    assert launched == []


def test_controller_stops_and_closes_on_expiry() -> None:
    events: list[Any] = []
    controller, guest, lifecycle, adapter = _make_controller(expire=True, events=events)
    guest_thread = threading.Thread(target=lambda: guest.bootstrap())
    guest_thread.start()
    with pytest.raises(WorkerTerminated, match="expired"):
        controller.run(
            run_id="run-1",
            token_id="token-1",
            nonce="nonce-1",
            workflow={},
            inputs={},
            contract=_contract(),
        )
    guest_thread.join(timeout=2)
    assert lifecycle.stop_calls == ["controller_failure"]
    assert adapter.closed == 1
    assert any(event.event == "revoke" for event in events)
    assert any(event.event == "wipe" for event in events)


def test_controller_rejects_stale_guest_receipt_and_cleans_once() -> None:
    controller, guest, lifecycle, adapter = _make_controller()

    def stale_guest() -> None:
        guest.bootstrap()
        guest.receive_run()
        result_without_hash = {"exit_status": 0}
        result_hash = _result_hash(result_without_hash)
        guest.send_receipt(
            {
                **_contract(),
                "schema": "testudo.guest.receipt.v1",
                "result_sha256": "b" * 64,
                "artifact_digest": "a" * 64,
            }
        )
        guest.send_result({**result_without_hash, "result_sha256": result_hash})

    guest_thread = threading.Thread(target=stale_guest)
    guest_thread.start()
    with pytest.raises(HostControllerError, match="receipt mismatch"):
        controller.run(
            run_id="run-1",
            token_id="token-1",
            nonce="nonce-1",
            workflow={},
            inputs={},
            contract=_contract(),
        )
    guest_thread.join(timeout=2)
    assert lifecycle.stop_calls == ["controller_failure"]
    assert adapter.closed == 1


def test_controller_rejects_terminal_result_hash_and_closes() -> None:
    controller, guest, lifecycle, adapter = _make_controller()

    def forged_guest() -> None:
        guest.bootstrap()
        guest.receive_run()
        guest.send_receipt(
            {
                **_contract(),
                "schema": "testudo.guest.receipt.v1",
                "result_sha256": "a" * 64,
                "artifact_digest": "a" * 64,
            }
        )
        guest.send_result({"exit_status": 0, "result_sha256": "a" * 64})

    guest_thread = threading.Thread(target=forged_guest)
    guest_thread.start()
    with pytest.raises(HostControllerError, match="result hash"):
        controller.run(
            run_id="run-1",
            token_id="token-1",
            nonce="nonce-1",
            workflow={},
            inputs={},
            contract=_contract(),
        )
    guest_thread.join(timeout=2)
    assert lifecycle.stop_calls == ["controller_failure"]
    assert adapter.closed == 1


def test_receipt_status_matches_exit_status_zero_and_nonzero() -> None:
    for exit_status, expected in ((0, "success"), (7, "failed")):
        events: list[Any] = []
        controller, guest, lifecycle, _adapter = _make_controller(status=exit_status, events=events)
        guest_thread = threading.Thread(
            target=_guest_success, args=(guest,), kwargs={"exit_status": exit_status}
        )
        guest_thread.start()
        result = controller.run(
            run_id="run-1",
            token_id="token-1",
            nonce="nonce-1",
            workflow={},
            inputs={},
            contract=_contract(),
        )
        guest_thread.join(timeout=2)
        assert not guest_thread.is_alive()
        assert result.exit_status == exit_status
        receipt_events = [event for event in events if event.event == "receipt"]
        assert len(receipt_events) == 1
        details = receipt_events[0].to_dict()["details"]
        assert details["status"] == expected
        assert details["exit_status"] == exit_status
        # The receipt digest binds the truthful status; a forged status would
        # not reproduce receipt_id.
        assert details["receipt_id"]
        del lifecycle


def test_host_receipt_rejects_status_that_contradicts_exit_status() -> None:
    from testudo.runtime.controller import HostControllerError, HostReceipt

    with pytest.raises(HostControllerError, match="match the verified exit_status"):
        HostReceipt(
            run_id="run-1",
            token_id="token-1",
            nonce="nonce-1",
            status="success",
            exit_status=7,
            result_sha256="a" * 64,
            guest_receipt={},
        )
    failed = HostReceipt(
        run_id="run-1",
        token_id="token-1",
        nonce="nonce-1",
        status="failed",
        exit_status=1,
        result_sha256="a" * 64,
        guest_receipt={},
    )
    assert failed.to_dict()["status"] == "failed"
