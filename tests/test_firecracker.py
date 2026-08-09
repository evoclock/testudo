# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Deterministic tests for the Firecracker/KVM host adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from testudo.runtime import firecracker


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
    rootfs = requests[2].body
    assert rootfs["is_root_device"] is True
    assert rootfs["is_read_only"] is True
    assert not any(request.path.startswith("/network-interfaces") for request in requests)
    assert requests[3].body == {"guest_cid": 3, "uds_path": "/run/testudo/export.sock"}


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
