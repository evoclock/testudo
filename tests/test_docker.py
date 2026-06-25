# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for ``testudo.runtime.docker``: argv construction and invoke wrapper.

Pure-Python tests cover ``build_docker_argv`` directly (no Docker needed) and
``invoke`` via a mocked ``subprocess.run``. The opt-in smoke test runs a real
``docker run hello-world`` and is auto-skipped when Docker is unavailable.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from testudo.runtime import docker
from testudo.runtime.isolation import IsolationProfile

# ----------------------------------------------------------------------------
# argv construction (pure)
# ----------------------------------------------------------------------------


@pytest.fixture
def workflow_file(tmp_path: Path) -> Path:
    path = tmp_path / "workflow.json"
    path.write_text('{"name": "test"}', encoding="utf-8")
    return path


@pytest.fixture
def runs_dir(tmp_path: Path) -> Path:
    target = tmp_path / "runs"
    target.mkdir()
    return target


@pytest.fixture
def inputs_dir(tmp_path: Path) -> Path:
    target = tmp_path / "inputs"
    target.mkdir()
    return target


def test_argv_starts_with_docker_run_rm(workflow_file: Path, runs_dir: Path) -> None:
    argv = docker.build_docker_argv(
        workflow_path=workflow_file,
        runs_dir=runs_dir,
        isolation=IsolationProfile(),
    )
    assert argv[:3] == ["docker", "run", "--rm"]


def test_argv_carries_default_resource_limits(workflow_file: Path, runs_dir: Path) -> None:
    argv = docker.build_docker_argv(
        workflow_path=workflow_file,
        runs_dir=runs_dir,
        isolation=IsolationProfile(),
    )
    assert "--cpus" in argv
    assert argv[argv.index("--cpus") + 1] == "1.0"
    assert "--memory" in argv
    assert argv[argv.index("--memory") + 1] == "2g"


def test_argv_uses_no_network_by_default(workflow_file: Path, runs_dir: Path) -> None:
    argv = docker.build_docker_argv(
        workflow_path=workflow_file,
        runs_dir=runs_dir,
        isolation=IsolationProfile(),
    )
    assert "--network" in argv
    assert argv[argv.index("--network") + 1] == "none"


def test_argv_sets_read_only_root_with_tmpfs(workflow_file: Path, runs_dir: Path) -> None:
    argv = docker.build_docker_argv(
        workflow_path=workflow_file,
        runs_dir=runs_dir,
        isolation=IsolationProfile(),
    )
    assert "--read-only" in argv
    assert "--tmpfs" in argv
    assert argv[argv.index("--tmpfs") + 1] == "/tmp"


def test_argv_drops_read_only_when_disabled(workflow_file: Path, runs_dir: Path) -> None:
    argv = docker.build_docker_argv(
        workflow_path=workflow_file,
        runs_dir=runs_dir,
        isolation=IsolationProfile(read_only=False),
    )
    assert "--read-only" not in argv
    assert "--tmpfs" not in argv


def test_argv_mounts_workflow_read_only(workflow_file: Path, runs_dir: Path) -> None:
    argv = docker.build_docker_argv(
        workflow_path=workflow_file,
        runs_dir=runs_dir,
        isolation=IsolationProfile(),
    )
    expected = f"{workflow_file.resolve()}:/workflow.json:ro"
    assert expected in argv


def test_argv_mounts_runs_dir_read_write(workflow_file: Path, runs_dir: Path) -> None:
    argv = docker.build_docker_argv(
        workflow_path=workflow_file,
        runs_dir=runs_dir,
        isolation=IsolationProfile(),
    )
    expected = f"{runs_dir.resolve()}:/runs"
    assert expected in argv
    # rw is the docker default; we deliberately do not append :ro to the runs mount
    assert f"{runs_dir.resolve()}:/runs:ro" not in argv


def test_argv_mounts_inputs_when_provided(
    workflow_file: Path, runs_dir: Path, inputs_dir: Path
) -> None:
    argv = docker.build_docker_argv(
        workflow_path=workflow_file,
        runs_dir=runs_dir,
        isolation=IsolationProfile(),
        inputs_dir=inputs_dir,
    )
    expected = f"{inputs_dir.resolve()}:/inputs:ro"
    assert expected in argv


def test_argv_omits_inputs_when_not_provided(workflow_file: Path, runs_dir: Path) -> None:
    argv = docker.build_docker_argv(
        workflow_path=workflow_file,
        runs_dir=runs_dir,
        isolation=IsolationProfile(),
    )
    assert "/inputs:ro" not in " ".join(argv)


def test_argv_ends_with_image_then_workflow_path(workflow_file: Path, runs_dir: Path) -> None:
    argv = docker.build_docker_argv(
        workflow_path=workflow_file,
        runs_dir=runs_dir,
        isolation=IsolationProfile(image="testudo:0.1"),
    )
    assert argv[-2] == "testudo:0.1"
    assert argv[-1] == "/workflow.json"


def test_argv_respects_custom_isolation_overrides(workflow_file: Path, runs_dir: Path) -> None:
    profile = IsolationProfile(
        image="testudo:dev", cpu="0.25", memory="256m", network="bridge", workdir="/w"
    )
    argv = docker.build_docker_argv(
        workflow_path=workflow_file, runs_dir=runs_dir, isolation=profile
    )
    assert argv[argv.index("--cpus") + 1] == "0.25"
    assert argv[argv.index("--memory") + 1] == "256m"
    assert argv[argv.index("--network") + 1] == "bridge"
    assert argv[argv.index("-w") + 1] == "/w"
    assert argv[-2] == "testudo:dev"


# ----------------------------------------------------------------------------
# invoke (subprocess mocked)
# ----------------------------------------------------------------------------


def test_invoke_returns_run_result_from_subprocess(
    monkeypatch: pytest.MonkeyPatch, workflow_file: Path, runs_dir: Path
) -> None:
    captured: dict[str, Any] = {}

    class FakeCompleted:
        returncode = 0
        stdout = "hello from container\n"
        stderr = ""

    def fake_run(argv: list[str], **kwargs: Any) -> FakeCompleted:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return FakeCompleted()

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = docker.invoke(
        workflow_path=workflow_file,
        runs_dir=runs_dir,
        isolation=IsolationProfile(),
    )
    assert isinstance(result, docker.RunResult)
    assert result.exit_status == 0
    assert result.stdout == "hello from container\n"
    assert result.stderr == ""
    assert result.runtime_ms >= 0
    assert captured["argv"][:3] == ["docker", "run", "--rm"]
    assert captured["kwargs"]["check"] is False
    assert captured["kwargs"]["capture_output"] is True


def test_invoke_passes_timeout_to_subprocess(
    monkeypatch: pytest.MonkeyPatch, workflow_file: Path, runs_dir: Path
) -> None:
    captured: dict[str, Any] = {}

    class FakeCompleted:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(argv: list[str], **kwargs: Any) -> FakeCompleted:
        captured["timeout"] = kwargs.get("timeout")
        return FakeCompleted()

    monkeypatch.setattr(subprocess, "run", fake_run)

    docker.invoke(
        workflow_path=workflow_file,
        runs_dir=runs_dir,
        isolation=IsolationProfile(),
        timeout=42.0,
    )
    assert captured["timeout"] == 42.0


def test_invoke_propagates_non_zero_exit_without_raising(
    monkeypatch: pytest.MonkeyPatch, workflow_file: Path, runs_dir: Path
) -> None:
    class FakeCompleted:
        returncode = 7
        stdout = ""
        stderr = "boom"

    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: FakeCompleted())

    result = docker.invoke(
        workflow_path=workflow_file,
        runs_dir=runs_dir,
        isolation=IsolationProfile(),
    )
    assert result.exit_status == 7
    assert result.stderr == "boom"


# ----------------------------------------------------------------------------
# Real-Docker smoke test (auto-skipped without Docker)
# ----------------------------------------------------------------------------


@pytest.mark.docker
def test_real_docker_hello_world(tmp_path: Path) -> None:
    """Invoke `docker run hello-world` to confirm the host has a working daemon.

    This test does not exercise the testudo image (which is not built by
    default in CI). It only sanity-checks that ``docker`` works from this
    host so the conftest.py docker marker correctly gates real-Docker tests.
    """
    if shutil.which("docker") is None:
        pytest.skip("docker not on PATH")

    completed = subprocess.run(
        ["docker", "run", "--rm", "hello-world"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "Hello from Docker" in completed.stdout
