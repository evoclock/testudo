# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for ``testudo.runtime.runner``: audit emission around docker.invoke."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from testudo.artifacts import ArtifactStore
from testudo.audit import AuditLog
from testudo.runtime import docker
from testudo.runtime.backend import ExecutionBackend
from testudo.runtime.controller import HostEvent, StopHandle
from testudo.runtime.isolation import IsolationProfile
from testudo.runtime.runner import Runner


@pytest.fixture
def workflow_file(tmp_path: Path) -> Path:
    path = tmp_path / "workflow.json"
    path.write_text('{"name": "demo"}', encoding="utf-8")
    return path


@pytest.fixture
def runs_root(tmp_path: Path) -> Path:
    return tmp_path / "runs"


def _stub_invoke(
    *,
    exit_status: int = 0,
    stdout: str = "",
    stderr: str = "",
    runtime_ms: int = 1,
) -> Callable[..., docker.RunResult]:
    def stub(**_kwargs: Any) -> docker.RunResult:
        return docker.RunResult(
            exit_status=exit_status,
            stdout=stdout,
            stderr=stderr,
            runtime_ms=runtime_ms,
        )

    return stub


class FakeRunnerController:
    def __init__(self, *, fail: bool = False, block: bool = False) -> None:
        self.fail = fail
        self.block = block
        self.calls: list[dict[str, Any]] = []
        self.started = threading.Event()
        self.release = threading.Event()
        self.stop_reason: str | None = None
        self._handle: StopHandle | None = None

    @property
    def stop_handle(self) -> StopHandle | None:
        return self._handle

    def _stop(self, reason: str) -> None:
        self.stop_reason = reason
        self.release.set()

    def run(self, **kwargs: Any) -> docker.RunResult:
        self.calls.append(kwargs)
        run_id = kwargs["run_id"]
        kwargs["event_sink"](
            HostEvent(
                event="transport",
                run_id=run_id,
                token_id="token-1",
                sequence=0,
                details={"phase": "ready"},
            )
        )
        self._handle = StopHandle(run_id, self._stop)
        self.started.set()
        if self.block:
            self.release.wait(timeout=2)
        if self.fail:
            raise RuntimeError("controller failed")
        return docker.RunResult(exit_status=0, stdout="controller", stderr="", runtime_ms=3)


def test_runner_defaults_to_microvm_and_fails_closed_without_adapter(
    workflow_file: Path, runs_root: Path
) -> None:
    runner = Runner(runs_root)
    with pytest.raises(RuntimeError, match="microVM backend"):
        runner.run(
            workflow_path=workflow_file,
            workflow_name="demo",
            isolation=IsolationProfile(),
        )


def test_runner_native_container_fails_closed_without_adapter(
    workflow_file: Path, runs_root: Path
) -> None:
    runner = Runner(runs_root, backend=ExecutionBackend.NATIVE_CONTAINER)
    with pytest.raises(RuntimeError, match="native-container backend"):
        runner.run(
            workflow_path=workflow_file,
            workflow_name="demo",
            isolation=IsolationProfile(),
            lease_id="lease-1",
            image_digest=f"sha256:{'a' * 64}",
        )


def test_runner_routes_native_container_without_mounting_host_authority(
    workflow_file: Path, runs_root: Path, tmp_path: Path
) -> None:
    lease = tmp_path / "lease.json"
    token = tmp_path / "capability-token.json"
    lease.write_text("{}")
    token.write_text("{}")
    controller = FakeRunnerController()
    digest = f"sha256:{'a' * 64}"
    runner = Runner(
        runs_root,
        backend=ExecutionBackend.NATIVE_CONTAINER,
        native_container_controller=controller,
    )

    result = runner.run(
        workflow_path=workflow_file,
        workflow_name="demo",
        isolation=IsolationProfile(image=f"testudo@{digest}"),
        lease_path=lease,
        capability_token_path=token,
        authorization_env={"CANTUS_APPROVAL_HASH": "approval"},
        lease_id="lease-1",
        image_digest=digest,
    )

    assert result.stdout == "controller"
    assert len(controller.calls) == 1
    call = controller.calls[0]
    assert call["lease_id"] == "lease-1"
    assert call["image_digest"] == digest
    assert call["lease_path"] is None
    assert call["capability_token_path"] is None
    assert call["attestation_path"] is None
    assert call["authorization_env"] is None
    run_dir = next(runs_root.iterdir())
    assert (run_dir / "runtime-attestation.json").is_file()
    events = AuditLog(run_dir / "audit.jsonl").read()
    assert events[0].args is not None
    assert events[0].args["backend"] == "native-container"
    assert events[0].args["contained"] is True


@pytest.mark.parametrize(
    ("lease_id", "image_digest", "image", "message"),
    [
        (None, f"sha256:{'a' * 64}", f"testudo@sha256:{'a' * 64}", "lease_id"),
        ("lease-1", None, "testudo:latest", "image_digest"),
        ("lease-1", f"sha256:{'a' * 64}", "testudo:latest", "pinned"),
    ],
)
def test_runner_native_container_requires_bound_identity_and_pinned_image(
    workflow_file: Path,
    runs_root: Path,
    lease_id: str | None,
    image_digest: str | None,
    image: str,
    message: str,
) -> None:
    runner = Runner(
        runs_root,
        backend="native-container",
        native_container_controller=FakeRunnerController(),
    )
    with pytest.raises(ValueError, match=message):
        runner.run(
            workflow_path=workflow_file,
            workflow_name="demo",
            isolation=IsolationProfile(image=image),
            lease_id=lease_id,
            image_digest=image_digest,
        )


def test_runner_can_use_explicit_microvm_adapter(workflow_file: Path, runs_root: Path) -> None:
    calls: list[dict[str, Any]] = []

    def microvm_invoke(**kwargs: Any) -> docker.RunResult:
        calls.append(kwargs)
        return docker.RunResult(exit_status=0, stdout="microvm", stderr="", runtime_ms=2)

    runner = Runner(runs_root, backend=ExecutionBackend.MICROVM, microvm_invoke=microvm_invoke)
    result = runner.run(
        workflow_path=workflow_file,
        workflow_name="demo",
        isolation=IsolationProfile(),
    )
    assert result.stdout == "microvm"
    assert len(calls) == 1


def test_runner_routes_microvm_controller_and_audits_host_events(
    workflow_file: Path, runs_root: Path
) -> None:
    controller = FakeRunnerController()
    runner = Runner(runs_root, microvm_controller=controller)

    result = runner.run(
        workflow_path=workflow_file,
        workflow_name="demo",
        isolation=IsolationProfile(),
    )

    assert result.stdout == "controller"
    assert len(controller.calls) == 1
    assert controller.calls[0]["workflow_path"] == workflow_file
    run_dir = next(runs_root.iterdir())
    events = AuditLog(run_dir / "audit.jsonl").read()
    assert [event.type for event in events] == ["workflow_start", "host_event", "workflow_end"]
    host_event = events[1]
    assert host_event.step_id == "transport"
    assert host_event.args is not None
    payload = host_event.args["host_event"]
    assert isinstance(payload, dict)
    assert payload["run_id"] == controller.calls[0]["run_id"]


def test_runner_controller_failure_audits_error_without_workflow_end(
    workflow_file: Path, runs_root: Path
) -> None:
    controller = FakeRunnerController(fail=True)
    runner = Runner(runs_root, microvm_controller=controller)

    with pytest.raises(RuntimeError, match="controller failed"):
        runner.run(
            workflow_path=workflow_file,
            workflow_name="demo",
            isolation=IsolationProfile(),
        )

    run_dir = next(runs_root.iterdir())
    events = AuditLog(run_dir / "audit.jsonl").read()
    assert [event.type for event in events] == ["workflow_start", "host_event", "error"]


def test_runner_exposes_controller_stop_handle_while_active(
    workflow_file: Path, runs_root: Path
) -> None:
    controller = FakeRunnerController(block=True)
    runner = Runner(runs_root, microvm_controller=controller)
    failures: list[BaseException] = []

    def execute() -> None:
        try:
            runner.run(
                workflow_path=workflow_file,
                workflow_name="demo",
                isolation=IsolationProfile(),
            )
        except BaseException as exc:  # pragma: no cover - assertion below catches failures
            failures.append(exc)

    thread = threading.Thread(target=execute)
    thread.start()
    assert controller.started.wait(timeout=2)
    handle = runner.stop_handle
    assert handle is not None
    assert handle.run_id == controller.calls[0]["run_id"]
    handle.stop("human_stop")
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert failures == []
    assert controller.stop_reason == "human_stop"
    assert runner.stop_handle is None


def test_runner_rejects_ambiguous_microvm_adapters(runs_root: Path) -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        Runner(runs_root, microvm_invoke=_stub_invoke(), microvm_controller=FakeRunnerController())


def test_runner_receipt_reset_happens_under_lock_after_active_run_check(
    workflow_file: Path, runs_root: Path
) -> None:
    """A refused concurrent run must not clear an in-flight run's host receipt."""
    receipts: dict[str, dict[str, object]] = {}

    class SequencedController:
        stop_handle = None

        def __init__(self) -> None:
            self._entered = threading.Event()
            self._release = threading.Event()

        def run(
            self,
            *,
            run_id: str,
            event_sink: Callable[[HostEvent], None],
            **_: object,
        ) -> docker.RunResult:
            receipts[run_id] = {"run_id": run_id}
            event_sink(
                HostEvent(
                    run_id=run_id,
                    token_id="token",
                    sequence=1,
                    event="receipt",
                    details=dict(receipts[run_id]),
                )
            )
            self._entered.set()
            self._release.wait(timeout=5)
            return docker.RunResult(exit_status=0, stdout="", stderr="", runtime_ms=1)

    controller = SequencedController()
    runner = Runner(runs_root, backend=ExecutionBackend.MICROVM, microvm_controller=controller)  # type: ignore[arg-type]
    workflow_path = workflow_file

    first = threading.Thread(
        target=runner.run,
        kwargs={
            "workflow_path": workflow_path,
            "workflow_name": "w",
            "isolation": IsolationProfile(),
            "run_id": "first",
        },
    )
    first.start()
    assert controller._entered.wait(timeout=5)

    with pytest.raises(RuntimeError, match="already has an active run"):
        runner.run(
            workflow_path=workflow_path,
            workflow_name="w",
            isolation=IsolationProfile(),
            run_id="second",
        )
    # The refused call did not clear the in-flight run's receipt.
    assert runner.last_host_receipt is not None
    assert runner.last_host_receipt["run_id"] == "first"
    controller._release.set()
    first.join(timeout=5)
    assert runner.last_host_receipt is not None
    assert runner.last_host_receipt["run_id"] == "first"


def test_runner_enforces_single_active_run_instance(workflow_file: Path, runs_root: Path) -> None:
    """A Runner instance executes one run at a time, fail-closed."""
    controller = FakeRunnerController(block=True)
    runner = Runner(runs_root, microvm_controller=controller)
    failures: list[BaseException] = []
    second_attempted = threading.Event()

    def execute() -> None:
        try:
            runner.run(
                workflow_path=workflow_file,
                workflow_name="demo",
                isolation=IsolationProfile(),
            )
        except BaseException as exc:  # pragma: no cover - assertion below catches failures
            failures.append(exc)

    thread = threading.Thread(target=execute)
    thread.start()
    assert controller.started.wait(timeout=2)

    with pytest.raises(RuntimeError, match="already has an active run"):
        runner.run(
            workflow_path=workflow_file,
            workflow_name="demo",
            isolation=IsolationProfile(),
        )
    second_attempted.set()
    controller.release.set()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert failures == []

    # After the first run finishes, the same instance may run again.
    result = runner.run(
        workflow_path=workflow_file,
        workflow_name="demo",
        isolation=IsolationProfile(),
    )
    assert result.stdout == "controller"


def test_runner_creates_per_run_directory(
    monkeypatch: pytest.MonkeyPatch, workflow_file: Path, runs_root: Path
) -> None:
    monkeypatch.setattr(docker, "invoke", _stub_invoke())

    runner = Runner(runs_root, backend="docker")
    runner.run(
        workflow_path=workflow_file,
        workflow_name="demo",
        isolation=IsolationProfile(),
    )

    run_dirs = [p for p in runs_root.iterdir() if p.is_dir()]
    assert len(run_dirs) == 1
    assert (run_dirs[0] / "audit.jsonl").is_file()


def test_runner_emits_workflow_start_then_workflow_end(
    monkeypatch: pytest.MonkeyPatch, workflow_file: Path, runs_root: Path
) -> None:
    monkeypatch.setattr(docker, "invoke", _stub_invoke(exit_status=0, runtime_ms=42))

    runner = Runner(runs_root, backend="docker")
    runner.run(
        workflow_path=workflow_file,
        workflow_name="demo",
        isolation=IsolationProfile(),
    )

    run_dir = next(runs_root.iterdir())
    events = AuditLog(run_dir / "audit.jsonl").read()
    assert [e.type for e in events] == ["workflow_start", "workflow_end"]
    assert events[0].workflow == "demo"
    assert events[1].exit_status == 0
    assert events[1].runtime_ms == 42


def test_runner_workflow_start_records_isolation_args(
    monkeypatch: pytest.MonkeyPatch, workflow_file: Path, runs_root: Path
) -> None:
    monkeypatch.setattr(docker, "invoke", _stub_invoke())

    runner = Runner(runs_root, backend="docker")
    runner.run(
        workflow_path=workflow_file,
        workflow_name="demo",
        isolation=IsolationProfile(memory="4g"),
    )

    run_dir = next(runs_root.iterdir())
    events = AuditLog(run_dir / "audit.jsonl").read()
    start = events[0]
    assert start.args is not None
    isolation_args = start.args["isolation"]
    assert isinstance(isolation_args, dict)
    assert isolation_args["memory"] == "4g"
    assert start.args["policy_sha256"] == IsolationProfile(memory="4g").policy_digest


def test_runner_emits_error_event_when_invoke_raises(
    monkeypatch: pytest.MonkeyPatch, workflow_file: Path, runs_root: Path
) -> None:
    def raising_invoke(**_kwargs: Any) -> docker.RunResult:
        raise RuntimeError("docker daemon not reachable")

    monkeypatch.setattr(docker, "invoke", raising_invoke)

    runner = Runner(runs_root, backend="docker")
    with pytest.raises(RuntimeError):
        runner.run(
            workflow_path=workflow_file,
            workflow_name="demo",
            isolation=IsolationProfile(),
        )

    run_dir = next(runs_root.iterdir())
    events = AuditLog(run_dir / "audit.jsonl").read()
    assert [e.type for e in events] == ["workflow_start", "error"]
    error_event = events[1]
    assert error_event.error is not None
    assert "docker daemon not reachable" in error_event.error
    assert "RuntimeError" in error_event.error


def test_runner_returns_run_result_from_invoke(
    monkeypatch: pytest.MonkeyPatch, workflow_file: Path, runs_root: Path
) -> None:
    monkeypatch.setattr(
        docker,
        "invoke",
        _stub_invoke(exit_status=0, stdout="ok", stderr="warn", runtime_ms=99),
    )

    runner = Runner(runs_root, backend="docker")
    result = runner.run(
        workflow_path=workflow_file,
        workflow_name="demo",
        isolation=IsolationProfile(),
    )
    assert result.exit_status == 0
    assert result.stdout == "ok"
    assert result.stderr == "warn"
    assert result.runtime_ms == 99


def test_runner_creates_runs_root_if_missing(
    monkeypatch: pytest.MonkeyPatch, workflow_file: Path, tmp_path: Path
) -> None:
    monkeypatch.setattr(docker, "invoke", _stub_invoke())

    nested = tmp_path / "deeply" / "nested" / "runs"
    runner = Runner(nested, backend="docker")
    assert nested.is_dir()

    runner.run(
        workflow_path=workflow_file,
        workflow_name="demo",
        isolation=IsolationProfile(),
    )
    run_dirs = [p for p in nested.iterdir() if p.is_dir()]
    assert len(run_dirs) == 1


def test_runner_mounts_exchange_not_audit_and_promotes_scanned_output(
    monkeypatch: pytest.MonkeyPatch, workflow_file: Path, runs_root: Path, tmp_path: Path
) -> None:
    captured: dict[str, Any] = {}

    def fake_invoke(**kwargs: Any) -> docker.RunResult:
        exchange = kwargs["runs_dir"]
        captured["runs_dir"] = exchange
        (exchange / "result.txt").write_text("accepted")
        return docker.RunResult(exit_status=0, stdout="", stderr="", runtime_ms=1)

    monkeypatch.setattr(docker, "invoke", fake_invoke)
    store = ArtifactStore(tmp_path / "store", store_id="mac-small")
    runner = Runner(runs_root, backend="docker")
    runner.run(
        workflow_path=workflow_file,
        workflow_name="demo",
        isolation=IsolationProfile(),
        artifact_store=store,
        egress_scanner=lambda path, relative: None,
        egress_scanner_id="test-scanner",
        egress_policy_hash="policy-test",
    )

    run_dir = next(runs_root.iterdir())
    assert captured["runs_dir"] == run_dir / "exchange"
    assert (run_dir / "audit.jsonl").is_file()
    assert (tmp_path / "store/runs").is_dir()
    assert len(list((tmp_path / "store/objects").rglob("*"))) >= 3


def test_runner_requires_scanner_for_artifact_store(
    workflow_file: Path, runs_root: Path, tmp_path: Path
) -> None:
    runner = Runner(runs_root, backend="docker")
    with pytest.raises(ValueError, match="egress_scanner"):
        runner.run(
            workflow_path=workflow_file,
            workflow_name="demo",
            isolation=IsolationProfile(),
            artifact_store=ArtifactStore(tmp_path / "store", store_id="linux-large"),
        )


def test_runner_contained_run_writes_attestation_and_passes_read_only_contract(
    monkeypatch: pytest.MonkeyPatch, workflow_file: Path, runs_root: Path, tmp_path: Path
) -> None:
    lease = tmp_path / "lease.json"
    token = tmp_path / "capability-token.json"
    lease.write_text("{}")
    token.write_text("{}")
    captured: dict[str, Any] = {}

    def fake_invoke(**kwargs: Any) -> docker.RunResult:
        captured.update(kwargs)
        return docker.RunResult(exit_status=0, stdout="", stderr="", runtime_ms=1)

    monkeypatch.setattr(docker, "invoke", fake_invoke)
    runner = Runner(runs_root, backend="docker")
    runner.run(
        workflow_path=workflow_file,
        workflow_name="demo",
        isolation=IsolationProfile(image=f"testudo@sha256:{'a' * 64}"),
        lease_path=lease,
        capability_token_path=token,
        authorization_env={"CANTUS_APPROVAL_HASH": "approval"},
        lease_id="lease-1",
        image_digest=f"sha256:{'a' * 64}",
    )

    run_dir = next(runs_root.iterdir())
    attestation = json.loads((run_dir / "runtime-attestation.json").read_text())
    assert attestation["runtime"] == "testudo"
    assert attestation["leaseId"] == "lease-1"
    assert captured["lease_path"] == lease
    assert captured["capability_token_path"] == token
    assert captured["attestation_path"] == run_dir / "runtime-attestation.json"
