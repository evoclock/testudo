"""Tests for ``testudo.runtime.runner``: audit emission around docker.invoke."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from testudo.audit import AuditLog
from testudo.runtime import docker
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
):
    def stub(**_kwargs: Any) -> docker.RunResult:
        return docker.RunResult(
            exit_status=exit_status,
            stdout=stdout,
            stderr=stderr,
            runtime_ms=runtime_ms,
        )

    return stub


def test_runner_creates_per_run_directory(
    monkeypatch: pytest.MonkeyPatch, workflow_file: Path, runs_root: Path
) -> None:
    monkeypatch.setattr(docker, "invoke", _stub_invoke())

    runner = Runner(runs_root)
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

    runner = Runner(runs_root)
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

    runner = Runner(runs_root)
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


def test_runner_emits_error_event_when_invoke_raises(
    monkeypatch: pytest.MonkeyPatch, workflow_file: Path, runs_root: Path
) -> None:
    def raising_invoke(**_kwargs: Any) -> docker.RunResult:
        raise RuntimeError("docker daemon not reachable")

    monkeypatch.setattr(docker, "invoke", raising_invoke)

    runner = Runner(runs_root)
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

    runner = Runner(runs_root)
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
    runner = Runner(nested)
    assert nested.is_dir()

    runner.run(
        workflow_path=workflow_file,
        workflow_name="demo",
        isolation=IsolationProfile(),
    )
    run_dirs = [p for p in nested.iterdir() if p.is_dir()]
    assert len(run_dirs) == 1
