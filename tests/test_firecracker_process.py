from __future__ import annotations

import io
import signal
import subprocess
from pathlib import Path

import pytest

from testudo.runtime import firecracker


class OutputProcess:
    pid: int | None = None

    def __init__(self, *, stdout: object = None, stderr: object = None) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.status: int | None = 0
        self.terminated = 0
        self.killed = 0

    def poll(self) -> int | None:
        return self.status

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        assert self.status is not None
        return self.status

    def terminate(self) -> None:
        self.terminated += 1
        self.status = -signal.SIGTERM

    def kill(self) -> None:
        self.killed += 1
        self.status = -signal.SIGKILL


class TreeProcess(OutputProcess):
    pid = 4242

    def __init__(self, *, timeout_once: bool = False) -> None:
        super().__init__()
        self.status = None
        self.timeout_once = timeout_once
        self.wait_calls = 0

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self.wait_calls += 1
        if self.timeout_once and self.wait_calls == 1:
            raise subprocess.TimeoutExpired("firecracker", 1)
        self.status = self.status if self.status is not None else 0
        return self.status


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
    )


def test_handle_collects_text_and_bytes_output(tmp_path: Path) -> None:
    process = OutputProcess(stdout=io.StringIO("stdout text"), stderr=io.BytesIO(b"stderr bytes"))
    handle = firecracker.FirecrackerHandle(
        _config(tmp_path), process, firecracker.FirecrackerAPI(tmp_path / "api.sock")
    )

    output = handle.collect_output()
    assert output.stdout == "stdout text"
    assert output.stderr == "stderr bytes"
    assert output.stdout_truncated is False
    assert output.stderr_truncated is False
    handle.cleanup()


def test_terminate_signals_start_new_session_process_group(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    process = TreeProcess()
    signals: list[tuple[int, int]] = []
    monkeypatch.setattr(firecracker.os, "killpg", lambda pid, sig: signals.append((pid, sig)))
    handle = firecracker.FirecrackerHandle(
        _config(tmp_path), process, firecracker.FirecrackerAPI(tmp_path / "api.sock")
    )

    handle.terminate()

    assert signals == [(4242, signal.SIGTERM)]
    assert process.terminated == 0
    assert process.wait_calls == 1


def test_terminate_escalates_process_group_after_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    process = TreeProcess(timeout_once=True)
    signals: list[tuple[int, int]] = []
    monkeypatch.setattr(firecracker.os, "killpg", lambda pid, sig: signals.append((pid, sig)))
    handle = firecracker.FirecrackerHandle(
        _config(tmp_path), process, firecracker.FirecrackerAPI(tmp_path / "api.sock")
    )

    handle.terminate(timeout=0.1)

    assert signals == [(4242, signal.SIGTERM), (4242, signal.SIGKILL)]
    assert process.wait_calls == 2


def test_terminate_falls_back_to_process_when_pid_is_unavailable(tmp_path: Path) -> None:
    process = OutputProcess()
    process.status = None
    handle = firecracker.FirecrackerHandle(
        _config(tmp_path), process, firecracker.FirecrackerAPI(tmp_path / "api.sock")
    )

    handle.terminate()

    assert process.terminated == 1
    assert process.killed == 0
