# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for ``testudo.runtime.isolation``: model defaults, frozen, loader."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from testudo.runtime.isolation import IsolationProfile, load_isolation

# ----------------------------------------------------------------------------
# Defaults and immutability
# ----------------------------------------------------------------------------


def test_isolation_defaults_are_secure() -> None:
    profile = IsolationProfile()
    assert profile.primitive == "docker"
    assert profile.image == "testudo:0.1"
    assert profile.cpu == "1.0"
    assert profile.memory == "2g"
    assert profile.network == "none"  # deny-by-default network
    assert profile.read_only is True  # deny-by-default writable root
    assert profile.rollback is True
    assert profile.workdir == "/runs"


def test_isolation_profile_is_frozen() -> None:
    profile = IsolationProfile()
    with pytest.raises(ValidationError):
        profile.image = "evil:latest"


def test_isolation_rejects_unknown_keys() -> None:
    with pytest.raises(ValidationError):
        IsolationProfile.model_validate({"image": "x", "kompromat": True})


def test_isolation_rejects_unknown_network_mode() -> None:
    with pytest.raises(ValidationError):
        IsolationProfile.model_validate({"network": "tor"})


def test_isolation_rejects_unknown_primitive() -> None:
    with pytest.raises(ValidationError):
        IsolationProfile.model_validate({"primitive": "qubes"})


# ----------------------------------------------------------------------------
# Loader
# ----------------------------------------------------------------------------


def test_load_isolation_returns_default_for_none() -> None:
    assert load_isolation(None) == IsolationProfile()


def test_load_isolation_returns_default_for_empty_dict() -> None:
    assert load_isolation({}) == IsolationProfile()


def test_load_isolation_from_full_block() -> None:
    block = {
        "primitive": "docker",
        "image": "testudo:0.1",
        "cpu": "0.5",
        "memory": "512m",
        "network": "bridge",
        "network_policy": {
            "phase": "evaluation",
            "purpose": "declared_api",
            "egress_hosts": ["api.example.com"],
            "egress_ports": [443],
            "methods": ["GET"],
            "max_bytes": 1_000_000,
            "max_duration_seconds": 30,
        },
        "rollback": False,
        "workdir": "/work",
        "read_only": False,
    }
    profile = load_isolation(block)
    assert profile.cpu == "0.5"
    assert profile.memory == "512m"
    assert profile.network == "bridge"
    assert profile.rollback is False
    assert profile.read_only is False


def test_load_isolation_from_partial_block_keeps_other_defaults() -> None:
    profile = load_isolation({"memory": "4g"})
    assert profile.memory == "4g"
    assert profile.cpu == "1.0"
    assert profile.network == "none"
    assert profile.read_only is True


def _microvm_block(**overrides: object) -> dict[str, object]:
    block: dict[str, object] = {
        "primitive": "microvm",
        "kernel_image": "/images/vmlinux",
        "rootfs": "/images/rootfs.ext4",
        "rootfs_format": "ext4",
        "vsock_socket": "/run/testudo/vsock.sock",
        "guest_cid": 3,
        "guest_port": 10000,
        "network": "none",
        "read_only": True,
    }
    block.update(overrides)
    return block


def test_microvm_profile_requires_typed_guest_boundary() -> None:
    profile = load_isolation(_microvm_block())
    assert profile.primitive == "microvm"
    assert profile.kernel_image == "/images/vmlinux"
    assert profile.rootfs == "/images/rootfs.ext4"
    assert profile.rootfs_format == "ext4"
    assert profile.vsock_socket == "/run/testudo/vsock.sock"
    assert profile.guest_cid == 3
    assert profile.guest_port == 10000


@pytest.mark.parametrize("network", ["bridge", "host"])
def test_microvm_rejects_networking(network: str) -> None:
    with pytest.raises(ValidationError, match="network='none'"):
        load_isolation(_microvm_block(network=network))


@pytest.mark.parametrize(
    "field",
    ["kernel_image", "rootfs", "rootfs_format", "vsock_socket", "guest_cid", "guest_port"],
)
def test_microvm_requires_all_guest_boundary_fields(field: str) -> None:
    block = _microvm_block()
    block.pop(field)
    with pytest.raises(ValidationError, match=field):
        load_isolation(block)


@pytest.mark.parametrize("field", ["guest_cid", "guest_port"])
def test_microvm_rejects_invalid_guest_numbers(field: str) -> None:
    with pytest.raises(ValidationError, match=field):
        load_isolation(_microvm_block(**{field: 0}))
    with pytest.raises(ValidationError, match=field):
        load_isolation(_microvm_block(**{field: 0x1_0000_0000}))


def test_microvm_requires_read_only_root() -> None:
    with pytest.raises(ValidationError, match="read_only=True"):
        load_isolation(_microvm_block(read_only=False))


def test_docker_rejects_microvm_only_fields() -> None:
    with pytest.raises(ValidationError, match="primitive='microvm'"):
        load_isolation({"primitive": "docker", "rootfs": "/images/rootfs.ext4"})
