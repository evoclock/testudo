# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bounded host-controller and receipt seam for one microVM run.

The controller owns protocol sequencing around injected worker adapters. It
does not create Firecracker processes, admit guest artifacts, or provide a
public Runner fallback. A later host adapter can implement the launcher
protocol using ``launch_worker`` and ``open_broker_session``.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal, Protocol, cast

from testudo.runtime.broker import BrokerSession
from testudo.runtime.docker import RunResult
from testudo.runtime.firecracker import MAX_OUTPUT_BYTES, FirecrackerOutput
from testudo.runtime.worker import WorkerLifecycle

HostEventName = Literal[
    "transport", "supervisor", "revoke", "wipe", "stdout", "stderr", "output", "receipt"
]
_IDENTITY_FIELDS = ("run_id", "token_id", "nonce")
_RECEIPT_SCHEMA = "testudo.host.receipt.v1"
_GUEST_RECEIPT_SCHEMA = "testudo.guest.receipt.v1"


class HostControllerError(RuntimeError):
    """A host-controller admission, protocol, receipt or lifecycle failure."""


class HostWorkerAdapter(Protocol):
    """Injected host worker boundary used by the desk-independent seam."""

    lifecycle: WorkerLifecycle
    broker: BrokerSession

    def collect_output(self, *, timeout: float | None = 5.0) -> FirecrackerOutput:
        """Return bounded host-observed stdout/stderr."""

    def close(self) -> None:
        """Close the broker and adapter-owned transient state."""


class HostWorkerLauncher(Protocol):
    def __call__(self, **kwargs: object) -> HostWorkerAdapter:
        """Launch one already-admitted worker through an injected adapter."""


def _canonical(value: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise HostControllerError("receipt payload is not canonical JSON") from exc


def _sha256(value: Mapping[str, object]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class HostEvent:
    """One sequenced, hash-bound controller event delivered to a sink."""

    event: HostEventName
    run_id: str
    token_id: str
    sequence: int
    details: Mapping[str, object]
    receipt_id: str = field(init=False)
    schema: str = field(init=False, default="testudo.host.event.v1")

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value for value in (self.run_id, self.token_id)):
            raise HostControllerError("host event identity is required")
        if self.sequence < 0:
            raise HostControllerError("host event sequence must be non-negative")
        details = MappingProxyType(dict(self.details))
        object.__setattr__(self, "details", details)
        payload = {
            "schema": self.schema,
            "event": self.event,
            "run_id": self.run_id,
            "token_id": self.token_id,
            "sequence": self.sequence,
            "details": dict(details),
        }
        object.__setattr__(self, "receipt_id", _sha256(payload))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "event": self.event,
            "run_id": self.run_id,
            "token_id": self.token_id,
            "sequence": self.sequence,
            "details": dict(self.details),
            "receipt_id": self.receipt_id,
        }


@dataclass(frozen=True, slots=True)
class HostReceipt:
    """Opaque guest receipt bound to the host-observed terminal result.

    ``status`` is derived from the verified terminal result, never asserted by
    the guest: ``success`` only when ``exit_status == 0``, ``failed``
    otherwise. The receipt is issued only after the guest result hash, guest
    receipt, and worker exit status all agree.
    """

    run_id: str
    token_id: str
    nonce: str
    status: Literal["success", "failed"]
    exit_status: int
    result_sha256: str
    guest_receipt: Mapping[str, object]
    receipt_id: str = field(init=False)
    schema: str = field(init=False, default=_RECEIPT_SCHEMA)

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str) and value
            for value in (self.run_id, self.token_id, self.nonce, self.result_sha256)
        ):
            raise HostControllerError("host receipt identity and result hash are required")
        if self.status not in ("success", "failed"):
            raise HostControllerError("host receipt status must be success or failed")
        if isinstance(self.exit_status, bool) or not isinstance(self.exit_status, int):
            raise HostControllerError("host receipt exit_status must be an integer")
        expected_status = "success" if self.exit_status == 0 else "failed"
        if self.status != expected_status:
            raise HostControllerError("host receipt status must match the verified exit_status")
        if len(self.result_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.result_sha256.lower()
        ):
            raise HostControllerError("host receipt result hash must be SHA-256")
        guest_receipt = MappingProxyType(dict(self.guest_receipt))
        object.__setattr__(self, "guest_receipt", guest_receipt)
        payload = {
            "schema": self.schema,
            "run_id": self.run_id,
            "token_id": self.token_id,
            "nonce": self.nonce,
            "status": self.status,
            "exit_status": self.exit_status,
            "result_sha256": self.result_sha256,
            "guest_receipt": dict(guest_receipt),
        }
        object.__setattr__(self, "receipt_id", _sha256(payload))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "run_id": self.run_id,
            "token_id": self.token_id,
            "nonce": self.nonce,
            "status": self.status,
            "exit_status": self.exit_status,
            "result_sha256": self.result_sha256,
            "guest_receipt": dict(self.guest_receipt),
            "receipt_id": self.receipt_id,
        }


@dataclass(frozen=True, slots=True)
class StopHandle:
    """Explicit governed stop handle for one active controller run."""

    run_id: str
    _stop: Callable[[str], None] = field(repr=False, compare=False)

    def stop(self, reason: str = "operator_stop") -> None:
        """Request a fail-closed lifecycle stop."""
        self._stop(reason)


class HostController:
    """Drive one injected broker/lifecycle worker and emit receipts."""

    def __init__(
        self,
        launcher: HostWorkerLauncher,
        *,
        event_sink: Callable[[HostEvent], None] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._launcher = launcher
        self._events = event_sink if event_sink is not None else (lambda _event: None)
        self._clock = clock
        self._active: HostWorkerAdapter | None = None
        self._active_run_id: str | None = None
        self._stop_called = False
        self._sequence = 0

    @property
    def stop_handle(self) -> StopHandle | None:
        """Return the active governed stop handle, if a run is active."""
        if self._active is None or self._active_run_id is None:
            return None
        return StopHandle(self._active_run_id, self.stop)

    def run(
        self,
        *,
        run_id: str,
        token_id: str,
        nonce: str,
        workflow: Mapping[str, Any],
        inputs: Mapping[str, Any],
        contract: Mapping[str, object],
        timeout: float | None = None,
        launch_kwargs: Mapping[str, object] | None = None,
    ) -> RunResult:
        """Launch an injected worker, execute framed run, and verify receipt."""
        self._validate_identity(run_id, token_id, nonce, contract)
        if not isinstance(workflow, Mapping) or not isinstance(inputs, Mapping):
            raise HostControllerError("workflow and inputs must be maps")
        if timeout is not None and timeout <= 0:
            raise HostControllerError("controller timeout must be positive")
        if self._active is not None:
            raise HostControllerError("a controller run is already active")

        self._sequence = 0
        self._stop_called = False
        started = self._clock()
        binding: HostWorkerAdapter | None = None
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        stdout_bytes = 0
        stderr_bytes = 0
        guest_receipt: Mapping[str, object] | None = None
        result_payload: dict[str, object] | None = None
        primary_error: BaseException | None = None
        try:
            kwargs = dict(launch_kwargs or {})
            kwargs.update(
                {
                    "run_id": run_id,
                    "token_id": token_id,
                    "nonce": nonce,
                    "workflow": dict(workflow),
                    "inputs": dict(inputs),
                    "contract": dict(contract),
                }
            )
            binding = self._launcher(**kwargs)
            self._active = binding
            self._active_run_id = run_id
            self._emit("transport", run_id, token_id, {"phase": "bootstrap"})
            binding.broker.bootstrap(contract)
            self._emit("transport", run_id, token_id, {"phase": "ready"})
            binding.broker.run(workflow, inputs)
            self._emit("transport", run_id, token_id, {"phase": "run"})

            deadline = None if timeout is None else started + timeout
            while True:
                binding.lifecycle.check()
                if deadline is not None and self._clock() >= deadline:
                    raise HostControllerError("controller run timed out")
                frame = binding.broker.receive()
                if frame.kind in {"stdout", "stderr"}:
                    chunk = frame.payload.get("chunk")
                    if not isinstance(chunk, str):
                        raise HostControllerError(f"{frame.kind} frame requires text chunk")
                    chunk_bytes = len(chunk.encode("utf-8"))
                    if frame.kind == "stdout":
                        stdout_bytes += chunk_bytes
                        if stdout_bytes > MAX_OUTPUT_BYTES:
                            raise HostControllerError("guest stdout exceeds bounded capture")
                        stdout_parts.append(chunk)
                    else:
                        stderr_bytes += chunk_bytes
                        if stderr_bytes > MAX_OUTPUT_BYTES:
                            raise HostControllerError("guest stderr exceeds bounded capture")
                        stderr_parts.append(chunk)
                    self._emit(
                        cast(HostEventName, frame.kind),
                        run_id,
                        token_id,
                        {"chunk": chunk, "sequence": frame.sequence},
                    )
                elif frame.kind == "receipt":
                    if guest_receipt is not None:
                        raise HostControllerError("duplicate guest receipt")
                    guest_receipt = dict(frame.payload)
                elif frame.kind == "result":
                    result_payload = dict(frame.payload)
                    break
                elif frame.kind == "error":
                    raise HostControllerError(f"guest execution failed: {dict(frame.payload)}")

            assert result_payload is not None
            binding.lifecycle.check()
            result_hash = result_payload.get("result_sha256")
            expected_hash = _sha256(
                {key: value for key, value in result_payload.items() if key != "result_sha256"}
            )
            if result_hash != expected_hash:
                raise HostControllerError("guest result hash does not match terminal payload")
            exit_status = result_payload.get("exit_status")
            if isinstance(exit_status, bool) or not isinstance(exit_status, int):
                raise HostControllerError("guest result exit_status must be an integer")
            if guest_receipt is None:
                raise HostControllerError("guest result is missing receipt")
            self._validate_guest_receipt(
                guest_receipt,
                run_id=run_id,
                token_id=token_id,
                nonce=nonce,
                result_hash=expected_hash,
                containment=contract.get("containment"),
            )
            remaining = None if deadline is None else max(0.0, deadline - self._clock())
            worker_status = binding.lifecycle.wait(timeout=remaining)
            if worker_status != exit_status:
                raise HostControllerError("worker exit status disagrees with guest result")
            host_output = binding.collect_output(timeout=remaining)
            stdout = "".join(stdout_parts) or host_output.stdout
            stderr = "".join(stderr_parts) or host_output.stderr
            self._emit(
                "output",
                run_id,
                token_id,
                {
                    "exit_status": exit_status,
                    "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
                    "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
                    "stdout_truncated": host_output.stdout_truncated,
                    "stderr_truncated": host_output.stderr_truncated,
                },
            )
            expected_status: Literal["success", "failed"] = (
                "success" if exit_status == 0 else "failed"
            )
            receipt = HostReceipt(
                run_id=run_id,
                token_id=token_id,
                nonce=nonce,
                status=expected_status,
                exit_status=exit_status,
                result_sha256=expected_hash,
                guest_receipt=guest_receipt,
            )
            self._emit("receipt", run_id, token_id, receipt.to_dict())
            self._emit(
                "supervisor",
                run_id,
                token_id,
                {"reason": "worker_exit", "exit_status": exit_status},
            )
            self._emit("revoke", run_id, token_id, {"reason": "worker_exit"})
            self._emit("wipe", run_id, token_id, {"reason": "worker_exit"})
            return RunResult(
                exit_status=exit_status,
                stdout=stdout,
                stderr=stderr,
                runtime_ms=int((self._clock() - started) * 1000),
            )
        except BaseException as exc:
            primary_error = exc
            if binding is not None:
                self._stop_after_failure(binding, run_id, token_id, exc)
            raise
        finally:
            if binding is not None:
                try:
                    binding.close()
                except BaseException as close_error:
                    if primary_error is None:
                        raise
                    primary_error.add_note(
                        f"controller close failed: {type(close_error).__name__}: {close_error}"
                    )
                finally:
                    self._active = None
                    self._active_run_id = None

    def stop(self, reason: str = "operator_stop") -> None:
        """Stop the active worker through broker and lifecycle boundaries."""
        binding = self._active
        run_id = self._active_run_id
        if binding is None or run_id is None:
            raise HostControllerError("no active controller run")
        if not reason:
            raise HostControllerError("stop reason is required")
        if self._stop_called:
            return
        self._stop_called = True
        self._emit(
            "supervisor", run_id, binding.lifecycle.supervisor.token.token_id, {"reason": reason}
        )
        # The lifecycle remains authoritative if the guest socket is already gone.
        with suppress(BaseException):
            binding.broker.stop(reason)
        binding.lifecycle.stop(reason)
        self._emit(
            "revoke", run_id, binding.lifecycle.supervisor.token.token_id, {"reason": reason}
        )
        self._emit("wipe", run_id, binding.lifecycle.supervisor.token.token_id, {"reason": reason})

    def _stop_after_failure(
        self,
        binding: HostWorkerAdapter,
        run_id: str,
        token_id: str,
        primary: BaseException,
    ) -> None:
        if self._stop_called:
            return
        self._stop_called = True
        for operation in (
            lambda: self._emit("supervisor", run_id, token_id, {"reason": "controller_failure"}),
            lambda: binding.lifecycle.stop("controller_failure"),
            lambda: self._emit("revoke", run_id, token_id, {"reason": "controller_failure"}),
            lambda: self._emit("wipe", run_id, token_id, {"reason": "controller_failure"}),
        ):
            try:
                operation()
            except BaseException as cleanup_error:
                primary.add_note(
                    f"controller cleanup failed: {type(cleanup_error).__name__}: {cleanup_error}"
                )

    def _emit(
        self,
        event: HostEventName,
        run_id: str,
        token_id: str,
        details: Mapping[str, object],
    ) -> None:
        record = HostEvent(event, run_id, token_id, self._sequence, dict(details))
        self._sequence += 1
        self._events(record)

    @staticmethod
    def _validate_identity(
        run_id: str,
        token_id: str,
        nonce: str,
        contract: Mapping[str, object],
    ) -> None:
        expected = {"run_id": run_id, "token_id": token_id, "nonce": nonce}
        if not all(isinstance(value, str) and value for value in expected.values()):
            raise HostControllerError("controller identity is required")
        for field_name in _IDENTITY_FIELDS:
            if contract.get(field_name) != expected[field_name]:
                raise HostControllerError(f"controller contract identity mismatch: {field_name}")

    @staticmethod
    def _validate_guest_receipt(
        receipt: Mapping[str, object],
        *,
        run_id: str,
        token_id: str,
        nonce: str,
        result_hash: str,
        containment: object = None,
    ) -> None:
        expected = {
            "schema": _GUEST_RECEIPT_SCHEMA,
            "run_id": run_id,
            "token_id": token_id,
            "nonce": nonce,
            "result_sha256": result_hash,
        }
        for field_name, value in expected.items():
            if receipt.get(field_name) != value:
                raise HostControllerError(f"guest receipt mismatch: {field_name}")
        if containment is not None:
            if not isinstance(containment, Mapping):
                raise HostControllerError("host containment contract is invalid")
            expected_containment = {**dict(containment), "monitor_active": True}
            if receipt.get("containment") != expected_containment:
                raise HostControllerError("guest receipt containment identity mismatch")
        elif "containment" in receipt:
            raise HostControllerError("guest receipt contains unrequested containment evidence")
        artifact_digest = receipt.get("artifact_digest")
        if (
            not isinstance(artifact_digest, str)
            or len(artifact_digest) != 64
            or any(character not in "0123456789abcdef" for character in artifact_digest.lower())
        ):
            raise HostControllerError("guest receipt artifact digest is invalid")


__all__ = [
    "HostController",
    "HostControllerError",
    "HostEvent",
    "HostReceipt",
    "HostWorkerAdapter",
    "HostWorkerLauncher",
    "StopHandle",
]
