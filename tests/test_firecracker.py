# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Deterministic tests for the Firecracker/KVM host adapter."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from testudo.runtime import firecracker
from testudo.runtime.capability import CapabilityError, CapabilityToken


def _config(tmp_path: Path, *, vsock: bool = True) -> firecracker.FirecrackerConfig:
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
        api_socket=tmp_path / "run" / "firecracker.api.sock",
        vsock_socket=(tmp_path / "run" / "export.sock") if vsock else None,
    )


def test_build_api_requests_has_read_only_rootfs_and_no_network() -> None:
    config = firecracker.FirecrackerConfig(
        binary=Path("/opt/firecracker"),
        kernel_image=Path("/images/vmlinux"),
        rootfs=Path("/images/rootfs.ext4"),
        api_socket=Path("/run/testudo/api.sock"),
        vsock_socket=Path("/run/testudo/export.sock"),
    )

    requests = firecracker.build_api_requests(config)

    assert [request.path for request in requests] == [
        "/machine-config",
        "/boot-source",
        "/drives/rootfs",
        "/vsock",
        "/actions",
    ]
    boot = requests[1].body
    assert boot["boot_args"] == (
        "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro rootfstype=ext4"
    )
    rootfs = requests[2].body
    assert rootfs["is_root_device"] is True
    assert rootfs["is_read_only"] is True
    assert not any(request.path.startswith("/network-interfaces") for request in requests)
    assert requests[3].body == {"guest_cid": 3, "uds_path": "/run/testudo/export.sock"}


def test_squashfs_boot_args_are_bound_to_read_only_root() -> None:
    config = firecracker.FirecrackerConfig(
        binary=Path("/opt/firecracker"),
        kernel_image=Path("/images/vmlinux"),
        rootfs=Path("/images/ubuntu.squashfs"),
        rootfs_format="squashfs",
        api_socket=Path("/run/testudo/api.sock"),
    )
    assert firecracker.build_api_requests(config)[1].body["boot_args"] == (
        "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro rootfstype=squashfs"
    )


def test_config_rejects_rootfs_boot_arg_override(tmp_path: Path) -> None:
    config = _config(tmp_path)
    invalid = firecracker.FirecrackerConfig(
        binary=config.binary,
        kernel_image=config.kernel_image,
        rootfs=config.rootfs,
        api_socket=Path("api.sock"),
        boot_args="console=ttyS0 root=/dev/evil rw",
    )
    with pytest.raises(firecracker.FirecrackerError, match="cannot override"):
        invalid.validate()


def test_config_rejects_writable_or_invalid_inputs(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.rootfs.unlink()
    with pytest.raises(firecracker.FirecrackerError, match="rootfs does not exist"):
        config.validate()

    config = _config(tmp_path)
    invalid = firecracker.FirecrackerConfig(
        binary=config.binary,
        kernel_image=config.kernel_image,
        rootfs=config.rootfs,
        api_socket=config.api_socket,
        guest_cid=2,
    )
    with pytest.raises(firecracker.FirecrackerError, match="guest CID"):
        invalid.validate()


def test_launch_configures_and_cleans_only_owned_sockets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    config = _config(tmp_path)
    config = firecracker.FirecrackerConfig(
        binary=config.binary,
        kernel_image=config.kernel_image,
        rootfs=config.rootfs,
        api_socket=Path("firecracker.api.sock"),
        vsock_socket=Path("export.sock"),
    )
    calls: list[firecracker.FirecrackerConfig] = []

    class FakeProcess:
        returncode = None

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float | None = None) -> int:
            self.returncode = 0
            return 0

        def terminate(self) -> None:
            self.returncode = 0

        def kill(self) -> None:
            self.returncode = -9

    process = FakeProcess()

    def fake_popen(argv: list[str], **kwargs: Any) -> FakeProcess:
        assert argv == config.argv()
        assert kwargs["start_new_session"] is True
        config.api_socket.parent.mkdir(parents=True, exist_ok=True)
        config.api_socket.touch()
        return process

    monkeypatch.setattr(
        firecracker.FirecrackerAPI,
        "configure_and_start",
        lambda self, received: calls.append(received),
    )

    handle = firecracker.launch(config, popen=fake_popen)
    assert calls == [config]
    assert handle.process is process
    handle.cleanup()
    assert not config.api_socket.exists()
    assert not config.vsock_socket.exists()  # type: ignore[union-attr]
    handle.cleanup()  # idempotent


def test_launch_refuses_to_remove_non_socket_stale_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    original = _config(tmp_path, vsock=False)
    config = firecracker.FirecrackerConfig(
        binary=original.binary,
        kernel_image=original.kernel_image,
        rootfs=original.rootfs,
        api_socket=Path("firecracker.api.sock"),
    )
    config.api_socket.write_text("not a socket")
    with pytest.raises(firecracker.FirecrackerError, match="non-socket"):
        firecracker.launch(config, popen=lambda *args, **kwargs: pytest.fail("must not launch"))


NOW = datetime(2026, 8, 8, 12, 0, tzinfo=UTC)


def _worker_token(*, lifetime: timedelta = timedelta(minutes=10)) -> CapabilityToken:
    return CapabilityToken.issue(
        signing_key=b"host-secret",
        run_id="run-1",
        lease_id="lease-1",
        host_id="mac-mini",
        vm_id="vm-1",
        repository="testudo",
        branch="agent/T-0254/run-1",
        base_sha="a" * 40,
        capabilities=("export",),
        lifetime=lifetime,
        now=NOW,
    )


def _worker_identity(token: CapabilityToken) -> dict[str, str]:
    return {name: getattr(token, name) for name in firecracker._IDENTITY_FIELDS}


class _FakeWorkerProcess:
    def __init__(self) -> None:
        self.status: int | None = None

    def poll(self) -> int | None:
        return self.status


class _FakeWorkerHandle:
    def __init__(self) -> None:
        self.process = _FakeWorkerProcess()
        self.terminated = 0
        self.cleaned = 0

    def terminate(self, *, timeout: float = 5.0) -> None:
        del timeout
        self.terminated += 1
        self.process.status = -15

    def cleanup(self) -> None:
        self.cleaned += 1


def test_launch_worker_verifies_and_binds_identity_before_launch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = _config(tmp_path)
    token = _worker_token()
    handle = _FakeWorkerHandle()
    calls: list[str] = []

    def fake_launch(received: firecracker.FirecrackerConfig, **kwargs: Any) -> _FakeWorkerHandle:
        del kwargs
        assert received is config
        calls.append("launch")
        return handle

    monkeypatch.setattr(firecracker, "launch", fake_launch)
    worker = firecracker.launch_worker(
        config,
        token,
        signing_key=b"host-secret",
        revoke_token=lambda token_id: calls.append(f"revoke:{token_id}"),
        wipe_vm=lambda: calls.append("wipe"),
        expected_identity=_worker_identity(token),
        now=lambda: NOW,
    )

    assert worker.supervisor.token.token_id == token.token_id
    assert calls == ["launch"]
    assert handle.terminated == 0
    assert handle.cleaned == 0


def test_launch_worker_rejects_expired_or_invalid_tokens_before_launch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = _config(tmp_path)
    launches: list[str] = []
    monkeypatch.setattr(
        firecracker,
        "launch",
        lambda *args, **kwargs: launches.append("launch"),
    )
    token = _worker_token(lifetime=timedelta(seconds=1))
    with pytest.raises(CapabilityError, match="expired"):
        firecracker.launch_worker(
            config,
            token,
            signing_key=b"host-secret",
            revoke_token=lambda _token_id: None,
            wipe_vm=lambda: None,
            now=lambda: NOW + timedelta(seconds=1),
        )

    tampered = token.to_dict()
    tampered["signature"] = "invalid"
    invalid = CapabilityToken._from_payload(
        {key: value for key, value in tampered.items() if key != "signature"}, "invalid"
    )
    with pytest.raises(CapabilityError, match="signature mismatch"):
        firecracker.launch_worker(
            config,
            invalid,
            signing_key=b"host-secret",
            revoke_token=lambda _token_id: None,
            wipe_vm=lambda: None,
            now=lambda: NOW,
        )

    assert launches == []


def test_launch_worker_rejects_mismatched_identity_before_launch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = _config(tmp_path)
    token = _worker_token()
    launches: list[str] = []
    monkeypatch.setattr(
        firecracker,
        "launch",
        lambda *args, **kwargs: launches.append("launch"),
    )

    expected = _worker_identity(token)
    expected["vm_id"] = "different-vm"
    with pytest.raises(CapabilityError, match="identity mismatch: vm_id"):
        firecracker.launch_worker(
            config,
            token,
            signing_key=b"host-secret",
            revoke_token=lambda _token_id: None,
            wipe_vm=lambda: None,
            expected_identity=expected,
            now=lambda: NOW,
        )
    assert launches == []


def test_launch_worker_launch_failure_cleans_once_and_preserves_primary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    original = _config(tmp_path)
    config = firecracker.FirecrackerConfig(
        binary=original.binary,
        kernel_image=original.kernel_image,
        rootfs=original.rootfs,
        api_socket=Path("firecracker.api.sock"),
        vsock_socket=Path("export.sock"),
    )
    monkeypatch.chdir(tmp_path)
    token = _worker_token()
    process = _FakeWorkerProcess()
    terminated: list[str] = []
    wiped: list[str] = []
    revoked: list[str] = []

    def fake_popen(argv: list[str], **kwargs: Any) -> _FakeWorkerProcess:
        del argv, kwargs
        config.api_socket.parent.mkdir(parents=True, exist_ok=True)
        config.api_socket.touch()
        return process

    def fail_start(
        self: firecracker.FirecrackerAPI, received: firecracker.FirecrackerConfig
    ) -> None:
        del self, received
        raise RuntimeError("primary launch failure")

    def terminate() -> None:
        terminated.append("terminate")
        process.status = -15

    monkeypatch.setattr(firecracker.FirecrackerAPI, "configure_and_start", fail_start)
    process.terminate = terminate  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="primary launch failure"):
        firecracker.launch_worker(
            config,
            token,
            signing_key=b"host-secret",
            revoke_token=lambda token_id: revoked.append(token_id),
            wipe_vm=lambda: wiped.append("wipe"),
            popen=fake_popen,
            now=lambda: NOW,
        )

    assert terminated == ["terminate"]
    assert revoked == [token.token_id]
    assert wiped == ["wipe"]
    assert not config.api_socket.exists()


def test_launch_worker_constructor_failure_attempts_every_cleanup_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = _config(tmp_path)
    token = _worker_token()
    handle = _FakeWorkerHandle()
    calls: list[str] = []

    monkeypatch.setattr(firecracker, "launch", lambda *args, **kwargs: handle)

    def fail_constructor(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise RuntimeError("primary constructor failure")

    monkeypatch.setattr(firecracker, "WorkerLifecycle", fail_constructor)
    with pytest.raises(RuntimeError, match="primary constructor failure"):
        firecracker.launch_worker(
            config,
            token,
            signing_key=b"host-secret",
            revoke_token=lambda token_id: calls.append(f"revoke:{token_id}"),
            wipe_vm=lambda: calls.append("wipe"),
            now=lambda: NOW,
        )

    assert calls == [f"revoke:{token.token_id}", "wipe"]
    assert handle.terminated == 1
    assert handle.cleaned == 1
