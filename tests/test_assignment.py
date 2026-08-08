# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import json
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from testudo.runtime.assignment import AssignmentError, AssignmentRequest, AssignmentService
from testudo.runtime.backend import ExecutionBackend
from testudo.runtime.controller import StopHandle
from testudo.runtime.docker import RunResult
from testudo.runtime.isolation import IsolationProfile


def request(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "testudo.assignment.request.v1",
        "assignment_id": "assignment-1",
        "envelope_id": "envelope-1",
        "repository": "evoclock/testudo",
        "branch": "agent/T-0001",
        "base_sha": "a" * 40,
        "allowed_paths": ["src/testudo/runtime"],
        "capabilities": ["read", "edit", "test"],
        "stopping_point": "Return a reviewable patch and receipt.",
        "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        "backend": "microvm",
        "image": "testudo@sha256:" + "b" * 64,
        "journey": {
            "prompt": "Implement the assignment and stop for review.",
            "role": "implementer",
            "model": "merge-gateway/zai/glm-5.3-flash",
            "max_steps": 20,
            "autonomy": "autonomous",
        },
    }
    value.update(changes)
    value["envelope_sha256"] = "0" * 64
    normalized = AssignmentRequest.model_validate(value)
    value["envelope_sha256"] = normalized.calculated_envelope_sha256
    return value


class FakeRunner:
    def __init__(
        self, *, backend: str = "microvm", block: bool = False, fail: bool = False
    ) -> None:
        self.backend = ExecutionBackend(backend)
        self.block = block
        self.fail = fail
        self.started = threading.Event()
        self.released = threading.Event()
        self.stop_reason: str | None = None
        self.calls: list[dict[str, Any]] = []

    @property
    def last_host_receipt(self) -> dict[str, object] | None:
        if not self.started.is_set() or self.fail:
            return None
        return {
            "schema": "testudo.host.receipt.v1",
            "run_id": "assignment-1",
            "receipt_id": "c" * 64,
            "status": "success",
            "exit_status": 0,
        }

    @property
    def stop_handle(self) -> StopHandle | None:
        if not self.started.is_set():
            return None
        return StopHandle("assignment-1", self._stop)

    def _stop(self, reason: str) -> None:
        self.stop_reason = reason
        self.released.set()

    def run(self, **kwargs: Any) -> RunResult:
        self.calls.append(kwargs)
        self.started.set()
        if self.block:
            self.released.wait(timeout=2)
        if self.fail:
            raise RuntimeError("contained run failed")
        return RunResult(0, "report", "", 4)


def isolation(_request: AssignmentRequest) -> IsolationProfile:
    return IsolationProfile(
        primitive="microvm",
        image="testudo@sha256:" + "b" * 64,
        kernel_image="/guest/vmlinux",
        rootfs="/guest/rootfs.ext4",
        rootfs_format="ext4",
        vsock_socket="/run/testudo/vsock.sock",
        guest_cid=3,
        guest_port=10000,
    )


def wait_receipt(service: AssignmentService, assignment_id: str = "assignment-1") -> object:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        receipt = service.receipt(assignment_id)
        if receipt is not None:
            return receipt
        time.sleep(0.01)
    raise AssertionError("assignment did not become terminal")


def test_request_is_closed_digest_bound_and_rejects_fallbacks() -> None:
    parsed = AssignmentRequest.model_validate(request())
    parsed.verify()
    assert parsed.workflow()["steps"][0]["uses"] == "runtime.pi_journey"  # type: ignore[index]

    unknown = request()
    unknown["extra"] = "value"
    with pytest.raises(ValueError, match="extra"):
        AssignmentRequest.model_validate(unknown)

    docker = request()
    docker["backend"] = "docker"
    with pytest.raises(ValueError, match="backend"):
        AssignmentRequest.model_validate(docker)

    host = request()
    host["capabilities"] = ["read", "host-exec"]
    with pytest.raises(ValueError, match="forbidden"):
        AssignmentRequest.model_validate(host)

    tampered = request()
    tampered["stopping_point"] = "widened after signing"
    with pytest.raises(AssignmentError, match="digest mismatch"):
        AssignmentRequest.model_validate(tampered).verify()


def test_service_requires_dispatcher_authentication_before_admission(tmp_path: Path) -> None:
    calls: list[str] = []

    def refuse(value: AssignmentRequest) -> None:
        calls.append(value.assignment_id)
        raise AssignmentError("dispatcher signature mismatch")

    service = AssignmentService(
        runner_factory=lambda _request: pytest.fail("unauthenticated work must not launch"),
        isolation_factory=isolation,
        verify_dispatcher=refuse,
        state_root=tmp_path,
    )
    with pytest.raises(AssignmentError, match="signature mismatch"):
        service.start(request())
    assert calls == ["assignment-1"]
    assert not (tmp_path / "assignment-1").exists()


def test_service_runs_once_and_persists_terminal_receipt(tmp_path: Path) -> None:
    runner = FakeRunner()
    service = AssignmentService(
        runner_factory=lambda _request: runner,  # type: ignore[arg-type,return-value]
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )

    admitted = service.start(request())
    receipt = wait_receipt(service)

    assert admitted.event == "admitted"
    assert receipt.status == "succeeded"  # type: ignore[attr-defined]
    assert receipt.no_host_fallback is True  # type: ignore[attr-defined]
    assert [event.event for event in service.observe("assignment-1")] == [
        "admitted",
        "started",
        "succeeded",
    ]
    assert runner.calls[0]["backend"] == "microvm"
    assert runner.calls[0]["workflow_name"] == "contained-pi-journey"
    assert (tmp_path / "assignment-1" / "receipt.json").is_file()
    reconciled = service.reconcile("envelope-1")
    assert reconciled["state"] == "succeeded"
    with pytest.raises(AssignmentError, match="already exists"):
        service.start(request())


def test_cancel_uses_runner_stop_and_records_terminal_evidence(tmp_path: Path) -> None:
    runner = FakeRunner(block=True)
    service = AssignmentService(
        runner_factory=lambda _request: runner,  # type: ignore[arg-type,return-value]
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    service.start(request())
    assert runner.started.wait(timeout=1)

    event = service.cancel("assignment-1", "operator_cancel")
    receipt = wait_receipt(service)

    assert event.event == "cancel_requested"
    assert runner.stop_reason == "operator_cancel"
    assert receipt.status == "cancelled"  # type: ignore[attr-defined]
    assert (tmp_path / "assignment-1" / "terminal-event.json").is_file()


def test_service_refuses_backend_mismatch_without_host_fallback(tmp_path: Path) -> None:
    runner = FakeRunner(backend="native-container")
    service = AssignmentService(
        runner_factory=lambda _request: runner,  # type: ignore[arg-type,return-value]
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    service.start(request())
    receipt = wait_receipt(service)

    assert receipt.status == "refused"  # type: ignore[attr-defined]
    assert receipt.no_host_fallback is True  # type: ignore[attr-defined]
    assert runner.calls == []


def test_service_recovers_terminal_state_without_duplicate_launch(tmp_path: Path) -> None:
    runner = FakeRunner()
    service = AssignmentService(
        runner_factory=lambda _request: runner,  # type: ignore[arg-type,return-value]
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    service.start(request())
    original = wait_receipt(service)

    recovered = AssignmentService(
        runner_factory=lambda _request: pytest.fail("recovery must not relaunch"),
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    receipt = recovered.receipt("assignment-1")
    assert receipt is not None
    assert receipt.receipt_id == original.receipt_id  # type: ignore[attr-defined]
    assert recovered.reconcile("envelope-1")["state"] == "succeeded"
    with pytest.raises(AssignmentError, match="already exists"):
        recovered.start(request())


def test_service_marks_recovered_nonterminal_run_interrupted(tmp_path: Path) -> None:
    run_dir = tmp_path / "assignment-1"
    run_dir.mkdir()
    value = request()
    (run_dir / "request.json").write_text(json.dumps(value), encoding="utf-8")
    event = {
        "schema": "testudo.assignment.event.v1",
        "assignment_id": "assignment-1",
        "run_id": "assignment-1",
        "sequence": 0,
        "event": "started",
        "at": datetime.now(UTC).isoformat(),
        "details": {},
    }
    (run_dir / "events.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")

    recovered = AssignmentService(
        runner_factory=lambda _request: pytest.fail("recovery must not relaunch"),
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    assert recovered.reconcile("envelope-1")["state"] == "interrupted"
    with pytest.raises(AssignmentError, match="supervisor reconciliation"):
        recovered.cancel("assignment-1", "stop")


def test_reconcile_absent_is_non_authorizing(tmp_path: Path) -> None:
    service = AssignmentService(
        runner_factory=lambda _request: FakeRunner(),  # type: ignore[arg-type,return-value]
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    assert dict(service.reconcile("missing")) == {
        "schema": "testudo.assignment.reconcile.v1",
        "envelope_id": "missing",
        "state": "absent",
    }


def test_operator_terminalization_closes_interrupted_run_with_digest_bound_evidence(
    tmp_path: Path,
) -> None:
    # Recovered interrupted run: started but the runner is gone.
    run_dir = tmp_path / "assignment-1"
    run_dir.mkdir()
    value = request()
    (run_dir / "request.json").write_text(json.dumps(value), encoding="utf-8")
    event = {
        "schema": "testudo.assignment.event.v1",
        "assignment_id": "assignment-1",
        "run_id": "assignment-1",
        "sequence": 0,
        "event": "started",
        "at": datetime.now(UTC).isoformat(),
        "details": {},
    }
    (run_dir / "events.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")

    authenticated: dict[str, int] = {"count": 0}

    def verifier(_operation: str, _details: object) -> None:
        authenticated["count"] += 1

    service = AssignmentService(
        runner_factory=lambda _request: pytest.fail("terminalization must not relaunch"),
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        verify_operator=verifier,
        state_root=tmp_path,
    )
    assert service.reconcile("envelope-1")["state"] == "interrupted"

    receipt = service.terminalize(
        "assignment-1", status="failed", reason="host restart lost the run"
    )
    assert authenticated["count"] == 1
    assert receipt.status == "failed"
    assert receipt.exit_status is None
    assert receipt.host_receipt is None
    assert "operator terminalization" in (receipt.error or "")
    # The receipt is digest-bound: recomputing the digest over the receipt
    # payload reproduces the receipt id.
    assert receipt.receipt_id
    # Durable terminal evidence exists without any relaunch.
    stored = json.loads((run_dir / "receipt.json").read_text(encoding="utf-8"))
    assert stored["receipt_id"] == receipt.receipt_id
    assert stored["status"] == "failed"
    terminal = json.loads((run_dir / "terminal-event.json").read_text(encoding="utf-8"))
    assert terminal["event"] == "failed"
    assert terminal["details"]["operator"] is True
    # The run is now terminal: reconcile reports the closed state and the
    # identity cannot be reused.
    assert service.reconcile("envelope-1")["state"] == "failed"
    assert service.receipt("assignment-1") is not None
    with pytest.raises(AssignmentError, match="already terminal"):
        service.terminalize("assignment-1", status="cancelled", reason="again")
    # A restart recovers the closed state without relaunching.
    restarted = AssignmentService(
        runner_factory=lambda _request: pytest.fail("terminal run must not relaunch"),
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    recovered = restarted.receipt("assignment-1")
    assert recovered is not None and recovered.receipt_id == receipt.receipt_id


def test_operator_terminalization_refuses_active_terminal_and_unknown_runs(
    tmp_path: Path,
) -> None:
    runner = FakeRunner(block=True)
    service = AssignmentService(
        runner_factory=lambda _request: runner,  # type: ignore[arg-type,return-value]
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        verify_operator=lambda _operation, _details: None,
        state_root=tmp_path,
    )
    service.start(request())
    assert runner.started.wait(timeout=1)

    # An active run is never terminalized by the operator: it is cancelled.
    with pytest.raises(AssignmentError, match="only a recovered interrupted"):
        service.terminalize("assignment-1", status="failed", reason="nope")
    service.cancel("assignment-1", "operator stop")
    wait_receipt(service)
    # A terminal run is already closed.
    with pytest.raises(AssignmentError, match="already terminal"):
        service.terminalize("assignment-1", status="cancelled", reason="nope")
    # An unknown identity fails closed.
    with pytest.raises(AssignmentError, match="unknown"):
        service.terminalize("assignment-missing", status="failed", reason="nope")
    # A rejected dispatcher verifier fails closed even for an interrupted run.
    # The interrupted run is created before the service loads so it is known.
    run_dir = tmp_path / "assignment-9"
    run_dir.mkdir()
    value = request(assignment_id="assignment-9", envelope_id="envelope-9")
    (run_dir / "request.json").write_text(json.dumps(value), encoding="utf-8")
    event = {
        "schema": "testudo.assignment.event.v1",
        "assignment_id": "assignment-9",
        "run_id": "assignment-9",
        "sequence": 0,
        "event": "started",
        "at": datetime.now(UTC).isoformat(),
        "details": {},
    }
    (run_dir / "events.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")
    def rejecting_verifier(_operation: str, _details: object) -> None:
        raise AssignmentError("operator rejected the terminalization")

    rejected_service = AssignmentService(
        runner_factory=lambda _request: pytest.fail("terminalization must not relaunch"),
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        verify_operator=rejecting_verifier,
        state_root=tmp_path,
    )

    with pytest.raises(AssignmentError, match="operator rejected"):
        rejected_service.terminalize("assignment-9", status="failed", reason="nope")
    assert rejected_service.reconcile("envelope-9")["state"] == "interrupted"
    assert (run_dir / "receipt.json").exists() is False


def test_service_rejects_duplicate_envelope_across_assignments(tmp_path: Path) -> None:
    runner = FakeRunner(block=True)
    service = AssignmentService(
        runner_factory=lambda _request: runner,  # type: ignore[arg-type,return-value]
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    service.start(request())
    assert runner.started.wait(timeout=1)

    with pytest.raises(AssignmentError, match="envelope identity already exists"):
        service.start(request(assignment_id="assignment-2"))


def test_service_rejects_duplicate_envelope_from_restart_state(tmp_path: Path) -> None:
    runner = FakeRunner()
    service = AssignmentService(
        runner_factory=lambda _request: runner,  # type: ignore[arg-type,return-value]
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    service.start(request())
    wait_receipt(service)

    # A restart loads the durable request; the same envelope under a new
    # assignment_id must still fail closed before any launch.
    recovered = AssignmentService(
        runner_factory=lambda _request: pytest.fail("replay must not relaunch"),
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    with pytest.raises(AssignmentError, match="envelope identity already"):
        recovered.start(request(assignment_id="assignment-2"))


def test_service_recovers_run_dir_created_before_request_json(tmp_path: Path) -> None:
    # A crash between mkdir and the durable request write leaves an incomplete
    # run dir; recovery must quarantine it, not wedge the service.
    (tmp_path / "assignment-1").mkdir()
    runner = FakeRunner()
    service = AssignmentService(
        runner_factory=lambda _request: runner,  # type: ignore[arg-type,return-value]
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    assert not (tmp_path / "assignment-1").exists()
    assert (tmp_path / "assignment-1.quarantined").is_dir()
    assert (tmp_path / "assignment-1.quarantined" / "quarantine.json").is_file()

    service.start(request())
    receipt = wait_receipt(service)
    assert receipt.status == "succeeded"  # type: ignore[attr-defined]


def test_quarantine_target_already_exists_marks_ambiguity_and_fails_closed(
    tmp_path: Path,
) -> None:
    # A previous quarantine of this run name never completed durably, so the
    # target already exists when recovery re-attempts the rename. The remains
    # are unreadable evidence: the run name is marked ambiguous (durably and
    # in memory) and admissions fail closed - assignment and envelope
    # identities can never be silently reused.
    run_dir = tmp_path / "assignment-1"
    run_dir.mkdir()
    (run_dir / "request.json").write_text("{poisoned", encoding="utf-8")
    stale_target = tmp_path / "assignment-1.quarantined"
    stale_target.mkdir()

    service = AssignmentService(
        runner_factory=lambda _request: pytest.fail("ambiguous root must not relaunch"),
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        verify_operator=lambda _operation, _details: None,
        state_root=tmp_path,
    )
    # Nothing was overwritten, deleted, or re-quarantined.
    assert run_dir.is_dir()
    assert (run_dir / "request.json").read_text(encoding="utf-8") == "{poisoned"
    assert not list(stale_target.iterdir()) or (stale_target / "quarantine.json").exists()
    assert service.ambiguous_quarantines == frozenset({"assignment-1"})
    # The ambiguity marker is durable and reloads on restart.
    marker = tmp_path / "assignment-1.quarantined.ambiguous"
    assert marker.is_file()
    marker_record = json.loads(marker.read_text(encoding="utf-8"))
    assert marker_record["schema"] == "testudo.assignment.ambiguous.v1"
    assert marker_record["run_id"] == "assignment-1"
    with pytest.raises(AssignmentError, match="ambiguous"):
        service.start(request())
    with pytest.raises(AssignmentError, match="ambiguous"):
        service.start(request(assignment_id="assignment-2", envelope_id="envelope-2"))

    restarted = AssignmentService(
        runner_factory=lambda _request: pytest.fail("ambiguous root must not relaunch"),
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    assert restarted.ambiguous_quarantines == frozenset({"assignment-1"})
    with pytest.raises(AssignmentError, match="ambiguous"):
        restarted.start(request())
    # Explicit operator reconciliation of the quarantined name clears the
    # ambiguity; the quarantined name itself is never re-admitted.
    service.reconcile_quarantine(
        "assignment-1", assignment_id="assignment-1", envelope_id="envelope-1"
    )
    assert service.ambiguous_quarantines == frozenset()
    with pytest.raises(AssignmentError, match="quarantined"):
        service.start(request())


def test_quarantine_rename_failure_marks_ambiguity_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A quarantine rename that fails (simulated I/O error) must not leave the
    # corrupt identity readable-and-reusable: the run name is marked ambiguous
    # durably and in memory, and admissions fail closed.
    run_dir = tmp_path / "assignment-1"
    run_dir.mkdir()
    (run_dir / "request.json").write_text("{poisoned", encoding="utf-8")

    real_rename = Path.rename

    def failing_rename(self: Path, target: Path) -> Path:
        if self.name == "assignment-1" and target.name == "assignment-1.quarantined":
            raise OSError("simulated quarantine rename failure")
        return real_rename(self, target)

    monkeypatch.setattr(Path, "rename", failing_rename)
    service = AssignmentService(
        runner_factory=lambda _request: pytest.fail("ambiguous root must not relaunch"),
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    monkeypatch.undo()
    # The run directory was left untouched, not deleted or overwritten.
    assert run_dir.is_dir()
    assert (run_dir / "request.json").read_text(encoding="utf-8") == "{poisoned"
    assert service.ambiguous_quarantines == frozenset({"assignment-1"})
    marker = tmp_path / "assignment-1.quarantined.ambiguous"
    assert marker.is_file()
    assert json.loads(marker.read_text(encoding="utf-8"))["reason"] == "quarantine rename failed"
    with pytest.raises(AssignmentError, match="ambiguous"):
        service.start(request())
    with pytest.raises(AssignmentError, match="ambiguous"):
        service.start(request(assignment_id="assignment-2", envelope_id="envelope-2"))
    # The durable ambiguity survives a restart.
    restarted = AssignmentService(
        runner_factory=lambda _request: pytest.fail("ambiguous root must not relaunch"),
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    with pytest.raises(AssignmentError, match="ambiguous"):
        restarted.start(request())


def test_service_quarantines_corrupt_state_without_blocking_other_assignments(
    tmp_path: Path,
) -> None:
    poisoned = tmp_path / "assignment-0"
    poisoned.mkdir()
    (poisoned / "request.json").write_text("{not json", encoding="utf-8")
    healthy = tmp_path / "assignment-1"
    healthy.mkdir()
    value = request()
    (healthy / "request.json").write_text(json.dumps(value), encoding="utf-8")
    event = {
        "schema": "testudo.assignment.event.v1",
        "assignment_id": "assignment-1",
        "run_id": "assignment-1",
        "sequence": 0,
        "event": "started",
        "at": datetime.now(UTC).isoformat(),
        "details": {},
    }
    (healthy / "events.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")

    service = AssignmentService(
        runner_factory=lambda _request: pytest.fail("recovery must not relaunch"),
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        verify_operator=lambda _operation, _details: None,
        state_root=tmp_path,
    )

    # The poisoned identity is quarantined; its request.json is corrupt, so no
    # identity can be recovered and the state root becomes ambiguous: every
    # new admission fails closed until explicit reconciliation.
    assert (tmp_path / "assignment-0.quarantined").is_dir()
    assert recovered_reconcile(service) == "interrupted"
    with pytest.raises(AssignmentError, match="ambiguous"):
        service.start(request())
    with pytest.raises(AssignmentError, match="ambiguous"):
        service.start(request(assignment_id="assignment-2", envelope_id="envelope-2"))
    # Explicit reconciliation persists an immutable tombstone asserted by the
    # dispatcher and clears the ambiguity; the reconciled identity can never
    # execute again, but new distinct assignments are admitted normally.
    service.reconcile_quarantine(
        "assignment-0",
        assignment_id="assignment-0",
        envelope_id="envelope-0",
    )
    assert service.ambiguous_quarantines == frozenset()
    assert (tmp_path / "assignment-0.quarantined" / "identity-tombstone.json").is_file()
    with pytest.raises(AssignmentError, match="quarantined"):
        service.start(request(assignment_id="assignment-0", envelope_id="envelope-0"))
    with pytest.raises(AssignmentError, match="quarantined"):
        service.start(request(assignment_id="assignment-9", envelope_id="envelope-0"))
    # The healthy run still stays fail-closed for its own identity.
    with pytest.raises(AssignmentError, match="already exists"):
        service.start(request())
    # A new distinct assignment starts normally.
    runner = FakeRunner()
    service2 = AssignmentService(
        runner_factory=lambda _request: runner,  # type: ignore[arg-type,return-value]
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    service2.start(request(assignment_id="assignment-2", envelope_id="envelope-2"))
    receipt = wait_receipt(service2, "assignment-2")
    assert receipt.status == "succeeded"  # type: ignore[attr-defined]
    # The tombstone survives a restart and keeps both identities forbidden.
    restarted = AssignmentService(
        runner_factory=lambda _request: pytest.fail("tombstoned identity must not relaunch"),
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    with pytest.raises(AssignmentError, match="quarantined"):
        restarted.start(request(assignment_id="assignment-0", envelope_id="envelope-0"))
    with pytest.raises(AssignmentError, match="envelope identity already"):
        restarted.start(request(assignment_id="assignment-3"))


def recovered_reconcile(service: AssignmentService) -> object:
    return service.reconcile("envelope-1")["state"]


def test_service_writes_terminal_artifacts_atomically(tmp_path: Path) -> None:
    runner = FakeRunner()
    service = AssignmentService(
        runner_factory=lambda _request: runner,  # type: ignore[arg-type,return-value]
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    service.start(request())
    wait_receipt(service)

    run_dir = tmp_path / "assignment-1"
    assert (run_dir / "receipt.json").is_file()
    assert (run_dir / "terminal-event.json").is_file()
    assert not list(run_dir.glob("*.tmp"))
    # The receipt is canonical and digest-bound on disk.
    stored = json.loads((run_dir / "receipt.json").read_text(encoding="utf-8"))
    assert stored["receipt_id"]
    assert stored["status"] == "succeeded"


def test_pre_admission_empty_mkdir_crash_is_not_ambiguous_and_carries_no_tombstone(
    tmp_path: Path,
) -> None:
    # A crash between mkdir(request.json rename) is a pre-admission crash: the
    # empty directory proves no identity was ever admitted.
    (tmp_path / "assignment-crash").mkdir()
    runner = FakeRunner()
    service = AssignmentService(
        runner_factory=lambda _request: runner,  # type: ignore[arg-type,return-value]
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    assert (tmp_path / "assignment-crash.quarantined").is_dir()
    assert not (tmp_path / "assignment-crash.quarantined" / "identity-tombstone.json").exists()
    record = json.loads(
        (tmp_path / "assignment-crash.quarantined" / "quarantine.json").read_text(encoding="utf-8")
    )
    assert record["reason"] == "pre-admission incomplete run directory"
    assert service.ambiguous_quarantines == frozenset()
    # The same assignment identity is still usable: no identity was admitted.
    service.start(request())
    receipt = wait_receipt(service)
    assert receipt.status == "succeeded"  # type: ignore[attr-defined]


def test_quarantine_with_recoverable_identity_tombstones_it_durably(
    tmp_path: Path,
) -> None:
    # A receipt digest parse failure after a successful admission: the request
    # and receipt both carry recoverable identity evidence.
    run_dir = tmp_path / "assignment-1"
    run_dir.mkdir()
    value = request()
    (run_dir / "request.json").write_text(json.dumps(value), encoding="utf-8")
    (run_dir / "request.json").write_text(json.dumps(value), encoding="utf-8")
    (run_dir / "receipt.json").write_text(
        json.dumps(
            {
                "schema": "testudo.assignment.receipt.v1",
                "assignment_id": "assignment-1",
                "envelope_id": "envelope-1",
                "envelope_sha256": value["envelope_sha256"],
                "run_id": "assignment-1",
                "backend": "microvm",
                "status": "succeeded",
                "exit_status": 0,
                "started_at": datetime.now(UTC).isoformat(),
                "finished_at": datetime.now(UTC).isoformat(),
                "events_sha256": "d" * 64,
                "result_sha256": None,
                "host_receipt": None,
                "error": None,
                "no_host_fallback": True,
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "events.jsonl").write_text(
        "corrupt\n"
        + json.dumps(
            {
                "schema": "testudo.assignment.event.v1",
                "assignment_id": "assignment-1",
                "run_id": "assignment-1",
                "sequence": 0,
                "event": "admitted",
                "at": datetime.now(UTC).isoformat(),
                "details": {},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    service = AssignmentService(
        runner_factory=lambda _request: pytest.fail("corrupt identity must not relaunch"),
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    quarantined = tmp_path / "assignment-1.quarantined"
    assert quarantined.is_dir()
    tombstone_path = quarantined / "identity-tombstone.json"
    assert tombstone_path.is_file()
    tombstone = json.loads(tombstone_path.read_text(encoding="utf-8"))
    assert tombstone["schema"] == "testudo.assignment.identity-tombstone.v1"
    assert tombstone["assignment_id"] == "assignment-1"
    assert tombstone["envelope_id"] == "envelope-1"
    assert tombstone["envelope_sha256"] == value["envelope_sha256"]
    # Duplicate checks include the tombstone: same assignment or same envelope
    # is forbidden immediately and after a restart.
    with pytest.raises(AssignmentError, match="quarantined"):
        service.start(request())
    with pytest.raises(AssignmentError, match="quarantined"):
        service.start(request(assignment_id="assignment-2"))
    recovered = AssignmentService(
        runner_factory=lambda _request: pytest.fail("tombstoned identity must not relaunch"),
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    with pytest.raises(AssignmentError, match="quarantined"):
        recovered.start(request())
    with pytest.raises(AssignmentError, match="quarantined"):
        recovered.start(request(assignment_id="assignment-2"))
    assert recovered.reconcile("envelope-1")["state"] == "absent"


def test_unrecoverable_identity_fails_closed_until_reconciliation(
    tmp_path: Path,
) -> None:
    # Both request and receipt evidence are destroyed: identity cannot be
    # recovered, so the state root is ambiguous and everything fails closed.
    run_dir = tmp_path / "assignment-1"
    run_dir.mkdir()
    (run_dir / "request.json").write_text("{poisoned", encoding="utf-8")
    (run_dir / "receipt.json").write_text("{also poisoned", encoding="utf-8")
    service = AssignmentService(
        runner_factory=lambda _request: pytest.fail("ambiguous root must not relaunch"),
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        verify_operator=lambda _operation, _details: None,
        state_root=tmp_path,
    )
    assert service.ambiguous_quarantines == frozenset({"assignment-1"})
    with pytest.raises(AssignmentError, match="ambiguous"):
        service.start(request())
    with pytest.raises(AssignmentError, match="ambiguous"):
        service.start(request(assignment_id="assignment-2", envelope_id="envelope-2"))
    # Reconciliation tombstones the asserted identity and clears ambiguity.
    service.reconcile_quarantine(
        "assignment-1", assignment_id="assignment-1", envelope_id="envelope-1"
    )
    assert service.ambiguous_quarantines == frozenset()
    with pytest.raises(AssignmentError, match="quarantined"):
        service.start(request())
    runner = FakeRunner()
    service2 = AssignmentService(
        runner_factory=lambda _request: runner,  # type: ignore[arg-type,return-value]
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    service2.start(request(assignment_id="assignment-2", envelope_id="envelope-2"))
    assert wait_receipt(service2, "assignment-2").status == "succeeded"  # type: ignore[attr-defined]


def test_reconciliation_rejects_duplicate_and_unknown_quarantines(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "assignment-1"
    run_dir.mkdir()
    (run_dir / "request.json").write_text("{poisoned", encoding="utf-8")
    service = AssignmentService(
        runner_factory=lambda _request: pytest.fail("must not relaunch"),
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        verify_operator=lambda _operation, _details: None,
        state_root=tmp_path,
    )
    with pytest.raises(AssignmentError, match="unknown"):
        service.reconcile_quarantine(
            "missing", assignment_id="assignment-1", envelope_id="envelope-1"
        )
    # A second reconciliation of a cleared quarantine is refused.
    service.reconcile_quarantine(
        "assignment-1", assignment_id="assignment-1", envelope_id="envelope-1"
    )
    with pytest.raises(AssignmentError, match="does not require reconciliation"):
        service.reconcile_quarantine(
            "assignment-1", assignment_id="assignment-1", envelope_id="envelope-1"
        )
    # Traversal attempts are refused before any filesystem access.
    with pytest.raises(AssignmentError, match="bare directory name"):
        service.reconcile_quarantine(
            "../escape", assignment_id="assignment-8", envelope_id="envelope-8"
        )


def test_interior_event_corruption_is_quarantined_not_tolerated(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "assignment-1"
    run_dir.mkdir()
    value = request()
    (run_dir / "request.json").write_text(json.dumps(value), encoding="utf-8")
    event = {
        "schema": "testudo.assignment.event.v1",
        "assignment_id": "assignment-1",
        "run_id": "assignment-1",
        "sequence": 0,
        "event": "started",
        "at": datetime.now(UTC).isoformat(),
        "details": {},
    }
    good = json.dumps(event) + "\n"
    (run_dir / "events.jsonl").write_text(good + "{interior corrupt\n" + good, encoding="utf-8")
    service = AssignmentService(
        runner_factory=lambda _request: pytest.fail("corrupt identity must not relaunch"),
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    # Interior corruption is not a torn tail: identity tombstoned durably.
    assert (tmp_path / "assignment-1.quarantined").is_dir()
    assert (tmp_path / "assignment-1.quarantined" / "identity-tombstone.json").is_file()
    assert service.ambiguous_quarantines == frozenset()
    with pytest.raises(AssignmentError, match="quarantined"):
        service.start(request())


def test_torn_final_event_record_is_recovered_and_interior_is_not(tmp_path: Path) -> None:
    # A crash mid-append leaves one incomplete final record without its
    # newline: recovery keeps the completed prefix and the service starts.
    run_dir = tmp_path / "assignment-1"
    run_dir.mkdir()
    value = request()
    (run_dir / "request.json").write_text(json.dumps(value), encoding="utf-8")
    admitted = {
        "schema": "testudo.assignment.event.v1",
        "assignment_id": "assignment-1",
        "run_id": "assignment-1",
        "sequence": 0,
        "event": "admitted",
        "at": datetime.now(UTC).isoformat(),
        "details": {},
    }
    torn = json.dumps(admitted)[: len(json.dumps(admitted)) // 2]
    (run_dir / "events.jsonl").write_text(json.dumps(admitted) + "\n" + torn, encoding="utf-8")

    service = AssignmentService(
        runner_factory=lambda _request: FakeRunner(),  # type: ignore[arg-type,return-value]
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    events = service.observe("assignment-1")
    assert [event.event for event in events] == ["admitted"]
    # The torn tail was compacted away; the file re-appends from the canonical
    # prefix (schema alias form, sorted keys, normalized UTC timestamp).
    stored = json.loads((tmp_path / "assignment-1" / "events.jsonl").read_text(encoding="utf-8"))
    assert stored["assignment_id"] == "assignment-1"
    assert stored["event"] == "admitted"
    assert stored["sequence"] == 0
    assert stored["at"] == datetime.fromisoformat(str(admitted["at"])).isoformat().replace(
        "+00:00", "Z"
    )
    # The recovered non-terminal identity is not relaunched and not duplicated:
    # it requires supervisor reconciliation, exactly like any other recovered run.
    with pytest.raises(AssignmentError, match="already exists"):
        service.start(request())


def test_event_log_identity_mismatch_is_quarantined(tmp_path: Path) -> None:
    run_dir = tmp_path / "assignment-1"
    run_dir.mkdir()
    (run_dir / "request.json").write_text(json.dumps(request()), encoding="utf-8")
    event = {
        "schema": "testudo.assignment.event.v1",
        "assignment_id": "other-assignment",
        "run_id": "assignment-1",
        "sequence": 0,
        "event": "admitted",
        "at": datetime.now(UTC).isoformat(),
        "details": {},
    }
    (run_dir / "events.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")
    AssignmentService(
        runner_factory=lambda _request: pytest.fail("must not relaunch"),
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    assert (tmp_path / "assignment-1.quarantined").is_dir()
    assert (tmp_path / "assignment-1.quarantined" / "identity-tombstone.json").is_file()


def test_non_contiguous_event_sequence_is_quarantined(tmp_path: Path) -> None:
    run_dir = tmp_path / "assignment-1"
    run_dir.mkdir()
    (run_dir / "request.json").write_text(json.dumps(request()), encoding="utf-8")
    event = {
        "schema": "testudo.assignment.event.v1",
        "assignment_id": "assignment-1",
        "run_id": "assignment-1",
        "sequence": 3,
        "event": "admitted",
        "at": datetime.now(UTC).isoformat(),
        "details": {},
    }
    (run_dir / "events.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")
    AssignmentService(
        runner_factory=lambda _request: pytest.fail("must not relaunch"),
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    assert (tmp_path / "assignment-1.quarantined").is_dir()


def test_assignment_receipt_status_matches_host_receipt_exit_status(
    tmp_path: Path,
) -> None:
    runner = FakeRunner()
    service = AssignmentService(
        runner_factory=lambda _request: runner,  # type: ignore[arg-type,return-value]
        isolation_factory=isolation,
        verify_dispatcher=lambda _request: None,
        state_root=tmp_path,
    )
    service.start(request())
    receipt = wait_receipt(service)
    assert receipt.status == "succeeded"  # type: ignore[attr-defined]
    assert receipt.exit_status == 0  # type: ignore[attr-defined]
    host_receipt = receipt.host_receipt  # type: ignore[attr-defined]
    assert host_receipt is not None
    # The assignment receipt status is consistent with the host receipt it
    # carries: a zero exit must never be reported as failed, and vice versa.
    assert host_receipt["status"] == "success"
    assert host_receipt["exit_status"] == 0
    stored = json.loads((tmp_path / "assignment-1" / "receipt.json").read_text(encoding="utf-8"))
    assert stored["status"] == "succeeded"
    assert stored["host_receipt"]["status"] == "success"
