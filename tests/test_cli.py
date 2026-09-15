# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for ``testudo.cli``: subcommand dispatch + run end-to-end."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from testudo.cli import execute_workflow, main
from testudo.runtime.docker import RunResult
from testudo.runtime.runner import Runner


@pytest.fixture
def workflow_file(tmp_path: Path) -> Path:
    spec = {
        "name": "demo",
        "steps": [{"id": "a", "uses": "noop", "with": {"k": "v"}}],
    }
    p = tmp_path / "wf.json"
    p.write_text(json.dumps(spec), encoding="utf-8")
    return p


def test_version_flag() -> None:
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "testudo" in result.output


def test_run_executes_noop_workflow(tmp_path: Path, workflow_file: Path) -> None:
    runs_dir = tmp_path / "runs"
    result = CliRunner().invoke(
        main,
        ["run", str(workflow_file), "--runs-dir", str(runs_dir), "--backend", "direct"],
    )
    assert result.exit_code == 0
    assert "[OK]" in result.stderr or "[OK]" in result.output
    # one run dir created
    run_dirs = list(runs_dir.iterdir())
    assert len(run_dirs) == 1
    assert (run_dirs[0] / "audit.jsonl").is_file()


def test_run_defaults_to_fail_closed_microvm(tmp_path: Path, workflow_file: Path) -> None:
    result = CliRunner().invoke(
        main,
        ["run", str(workflow_file), "--runs-dir", str(tmp_path / "runs")],
    )
    assert result.exit_code == 2
    assert "no host microVM adapter is configured" in (result.stderr or result.output)
    assert not (tmp_path / "runs").exists() or not list((tmp_path / "runs").iterdir())


def test_execute_workflow_accepts_host_supplied_runner(tmp_path: Path, workflow_file: Path) -> None:
    from testudo.orchestrator import load_workflow

    class FakeContainedController:
        @property
        def stop_handle(self) -> None:
            return None

        def run(self, **kwargs: object) -> RunResult:
            assert kwargs["workflow_path"] == workflow_file
            return RunResult(
                exit_status=0,
                stdout=json.dumps({"exit_status": 0, "steps": {"a": {"output": {"ok": True}}}}),
                stderr="",
                runtime_ms=3,
            )

    runs_root = tmp_path / "runs"
    rid, run_dir, result = execute_workflow(
        workflow_path=workflow_file,
        workflow=load_workflow(workflow_file),
        inputs={"answer": 42},
        runs_dir=runs_root,
        run_id="cli-contained-1",
        runner=Runner(runs_root, microvm_controller=FakeContainedController()),  # type: ignore[arg-type]
    )

    assert rid == "cli-contained-1"
    assert isinstance(result, RunResult)
    assert run_dir == runs_root / rid
    assert json.loads((run_dir / "inputs" / "inputs.json").read_text()) == {"answer": 42}


def test_run_returns_non_zero_on_unknown_tool(tmp_path: Path) -> None:
    bad = {
        "name": "broken",
        "steps": [{"id": "a", "uses": "ghost.tool"}],
    }
    p = tmp_path / "broken.json"
    p.write_text(json.dumps(bad), encoding="utf-8")
    result = CliRunner().invoke(
        main,
        [
            "run",
            str(p),
            "--runs-dir",
            str(tmp_path / "runs"),
            "--backend",
            "direct",
        ],
    )
    assert result.exit_code == 1
    assert "[FAIL]" in (result.stderr or result.output)


def test_inspect_prints_audit_events(tmp_path: Path, workflow_file: Path) -> None:
    runs_dir = tmp_path / "runs"
    CliRunner().invoke(
        main,
        ["run", str(workflow_file), "--runs-dir", str(runs_dir), "--backend", "direct"],
    )
    audit_path = next(runs_dir.iterdir()) / "audit.jsonl"

    result = CliRunner().invoke(main, ["inspect", str(audit_path)])
    assert result.exit_code == 0
    assert "step_start" in result.output or "workflow_start" in result.output
