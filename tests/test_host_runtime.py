# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for host-supervisor-owned governed Runner construction."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import testudo.runtime.host_runtime as host_runtime
from testudo.runtime.docker import RunResult
from testudo.runtime.firecracker_adapter import FirecrackerAdapter
from testudo.runtime.host_runtime import (
    GovernedNativeContainerRunnerConfig,
    GovernedRunnerConfig,
    build_governed_runner,
)
from testudo.runtime.isolation import IsolationProfile
from testudo.runtime.native_container import NativeContainerAdapter
from testudo.runtime.runner import Runner, RunnerAuthorization
from testudo.runtime.signing import P256Signer


def _executable(tmp_path: Path) -> Path:
    binary = tmp_path / "firecracker"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o700)
    return binary


def _native_executable(tmp_path: Path) -> Path:
    binary = tmp_path / "container"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o700)
    return binary


def _authorization(run_id: str) -> RunnerAuthorization:
    return RunnerAuthorization(
        lease_path=Path(f"/authority/{run_id}/lease.json"),
        capability_token_path=Path(f"/authority/{run_id}/token.json"),
        authorization_env={"CANTUS_TASK_HASH": "task-hash"},
        lease_id="lease-1",
        image_digest="sha256:" + "a" * 64,
    )


def test_governed_config_builds_no_process_runner(tmp_path: Path) -> None:
    revoked: list[str] = []
    wiped: list[bool] = []

    config = GovernedRunnerConfig(
        runs_root=tmp_path / "runs",
        firecracker_binary=_executable(tmp_path),
        host_id="linux-backend",
        repository="testudo",
        branch="agent/containment",
        base_sha="a" * 40,
        authorization_provider=_authorization,
        revoke_token=revoked.append,
        wipe_vm=lambda: wiped.append(True),
        signer=P256Signer.generate("test-token-key"),
    )

    runner = build_governed_runner(config)

    assert runner.backend.value == "microvm"
    assert isinstance(runner.microvm_controller, FirecrackerAdapter)
    assert revoked == []
    assert wiped == []
    assert not (tmp_path / "runs").exists() or not any((tmp_path / "runs").iterdir())


def test_native_governed_config_builds_explicit_adapter_without_process(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(host_runtime.sys, "platform", "darwin")
    revoked: list[object] = []
    wiped: list[object] = []
    image_checks: list[str] = []
    config = GovernedNativeContainerRunnerConfig(
        runs_root=tmp_path / "runs",
        container_binary=_native_executable(tmp_path),
        authorization_provider=_authorization,
        image_exists=lambda image: image_checks.append(image) is None,
        revoke_token=revoked.append,
        wipe_container=wiped.append,
    )

    runner = build_governed_runner(config)

    assert runner.backend.value == "native-container"
    assert isinstance(runner.native_container_controller, NativeContainerAdapter)
    assert runner.microvm_controller is None
    assert revoked == []
    assert wiped == []
    assert image_checks == []
    assert not (tmp_path / "runs").exists() or not any((tmp_path / "runs").iterdir())


def test_native_governed_config_fails_closed_off_macos(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(host_runtime.sys, "platform", "linux")
    with pytest.raises(ValueError, match="require macOS"):
        GovernedNativeContainerRunnerConfig(
            runs_root=tmp_path / "runs",
            container_binary=_native_executable(tmp_path),
            authorization_provider=_authorization,
            image_exists=lambda _image: True,
            revoke_token=lambda *_args: None,
            wipe_container=lambda *_args: None,
        )


def test_native_governed_config_rejects_non_apple_binary_and_missing_admission(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(host_runtime.sys, "platform", "darwin")
    wrong_binary = _executable(tmp_path)
    with pytest.raises(ValueError, match="Apple container binary"):
        GovernedNativeContainerRunnerConfig(
            runs_root=tmp_path / "runs",
            container_binary=wrong_binary,
            authorization_provider=_authorization,
            image_exists=lambda _image: True,
            revoke_token=lambda *_args: None,
            wipe_container=lambda *_args: None,
        )

    with pytest.raises(ValueError, match="local image admission"):
        GovernedNativeContainerRunnerConfig(
            runs_root=tmp_path / "runs",
            container_binary=_native_executable(tmp_path),
            authorization_provider=_authorization,
            image_exists=None,  # type: ignore[arg-type]
            revoke_token=lambda *_args: None,
            wipe_container=lambda *_args: None,
        )


def test_governed_factory_rejects_unknown_config() -> None:
    with pytest.raises(TypeError, match="unsupported governed Runner"):
        build_governed_runner(object())  # type: ignore[arg-type]


def test_governed_config_requires_explicit_verifier_and_callbacks(tmp_path: Path) -> None:
    common: dict[str, Any] = {
        "runs_root": tmp_path / "runs",
        "firecracker_binary": _executable(tmp_path),
        "host_id": "linux-backend",
        "repository": "testudo",
        "branch": "agent/containment",
        "base_sha": "a" * 40,
        "authorization_provider": _authorization,
        "revoke_token": lambda _token_id: None,
        "wipe_vm": lambda: None,
    }

    with pytest.raises(ValueError, match="exactly one capability-token verifier"):
        GovernedRunnerConfig(**common)
    with pytest.raises(ValueError, match="exactly one capability-token verifier"):
        GovernedRunnerConfig(
            **common,
            signing_key=b"test-key",
            signer=P256Signer.generate("test-token-key"),
        )


def test_runner_refreshes_authorization_for_each_run(tmp_path: Path) -> None:
    workflow_path = tmp_path / "workflow.json"
    workflow_path.write_text(json.dumps({"name": "demo"}), encoding="utf-8")
    calls: list[str] = []

    class Controller:
        @property
        def stop_handle(self) -> None:
            return None

        def run(self, **_kwargs: object) -> RunResult:
            return RunResult(exit_status=0, stdout="ok", stderr="", runtime_ms=1)

    def provider(run_id: str) -> RunnerAuthorization:
        calls.append(run_id)
        return _authorization(run_id)

    runner = Runner(
        tmp_path / "runs",
        microvm_controller=Controller(),
        authorization_provider=provider,
    )
    image = "testudo@sha256:" + "a" * 64
    isolation = IsolationProfile(image=image)

    runner.run(
        workflow_path=workflow_path,
        workflow_name="demo",
        isolation=isolation,
        run_id="run-one",
    )
    runner.run(
        workflow_path=workflow_path,
        workflow_name="demo",
        isolation=isolation,
        run_id="run-two",
    )

    assert calls == ["run-one", "run-two"]
