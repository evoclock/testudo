# SPDX-FileCopyrightText: 2026 Julen Gamboa <julen.gamboa@example.invalid>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for phase-bound runtime storage and network policy contracts."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from testudo.runtime.isolation import IsolationProfile, load_isolation
from testudo.runtime.policy import NetworkPolicy, StoragePolicy, policy_digest


def _network(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "phase": "provision",
        "purpose": "dependency_fetch",
        "egress_hosts": ("pypi.org",),
        "egress_ports": (443,),
        "methods": ("GET", "HEAD"),
        "max_bytes": 10_000_000,
        "max_duration_seconds": 120,
    }
    value.update(overrides)
    return value


def test_runtime_policies_default_deny_and_use_run_local_storage() -> None:
    storage = StoragePolicy()
    network = NetworkPolicy()
    assert storage.host_scope == "run_local"
    assert storage.workspace == "/runs"
    assert storage.inputs == "/inputs"
    assert storage.host_mounts == ()
    assert network.purpose == "none"
    assert network.egress_hosts == ()
    assert policy_digest(storage, network) == policy_digest(StoragePolicy(), NetworkPolicy())


def test_provision_storage_can_write_a_local_dependency_cache() -> None:
    policy = StoragePolicy(
        phase="provision",
        cache="/cache/dependencies",
        cache_access="read_write",
    )
    assert policy.cache == "/cache/dependencies"


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"host_mounts": ("/Users",)}, "host mounts"),
        ({"cache": "/cache/dependencies"}, "cache_access"),
        ({"cache_access": "read_only"}, "explicit cache path"),
        (
            {"phase": "evaluation", "cache": "/cache/dependencies", "cache_access": "read_write"},
            "evaluation",
        ),
        ({"workspace": "/"}, "workspace"),
        ({"inputs": "/inputs/../host"}, "inputs"),
        ({"workspace": "/runs/a b"}, "canonical guest path"),
        ({"workspace": "/runs/a\tb"}, "canonical guest path"),
        ({"inputs": "/inputs/ "}, "canonical guest path"),
        ({"workspace": "/runs/a\nb"}, "canonical guest path"),
    ],
)
def test_storage_policy_rejects_unsafe_shapes(kwargs: dict[str, object], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        StoragePolicy.model_validate(kwargs)


def test_network_purpose_rules_allow_provision_and_research_but_not_eval_lookup() -> None:
    provision = NetworkPolicy.model_validate(_network(cache_write=True))
    assert provision.purpose == "dependency_fetch"
    assert provision.cache_write is True
    research = NetworkPolicy.model_validate(
        _network(phase="research", purpose="resource_lookup", cache_write=False)
    )
    assert research.phase == "research"
    with pytest.raises(ValidationError, match="forbidden during evaluation"):
        NetworkPolicy.model_validate(_network(phase="evaluation", purpose="resource_lookup"))


def test_declared_evaluation_api_requires_limits_and_allowlist() -> None:
    policy = NetworkPolicy.model_validate(
        _network(phase="evaluation", purpose="declared_api", methods=("POST",))
    )
    assert policy.methods == ("POST",)
    with pytest.raises(ValidationError, match="hosts, ports and methods"):
        NetworkPolicy.model_validate({"phase": "evaluation", "purpose": "declared_api"})


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"purpose": "none", "egress_hosts": ("example.com",)}, "purpose='none'"),
        ({**_network(), "egress_hosts": ("*.example.com",)}, "exact hostnames"),
        ({**_network(), "egress_ports": (0,)}, "between 1 and 65535"),
        ({**_network(), "methods": ("TRACE",)}, "unsupported HTTP"),
        ({**_network(), "max_bytes": 0}, "positive max_bytes"),
        ({**_network(), "max_duration_seconds": 0}, "positive max_duration_seconds"),
        ({**_network(), "cache_write": True, "purpose": "declared_api"}, "only provision"),
    ],
)
def test_network_policy_rejects_unsafe_or_incomplete_shapes(
    kwargs: dict[str, object], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        NetworkPolicy.model_validate(kwargs)


def test_isolation_binds_both_policies_and_digest() -> None:
    profile = load_isolation(
        {
            "storage_policy": {
                "phase": "provision",
                "cache": "/cache/dependencies",
                "cache_access": "read_write",
            },
            "network_policy": _network(cache_write=True),
        }
    )
    assert profile.storage_policy.cache_access == "read_write"
    assert profile.network_policy.purpose == "dependency_fetch"
    assert len(profile.policy_digest) == 64


def test_microvm_profile_keeps_backend_network_off_for_declarative_policy() -> None:
    profile = IsolationProfile(
        primitive="microvm",
        kernel_image="/images/vmlinux",
        rootfs="/images/rootfs.ext4",
        rootfs_format="ext4",
        vsock_socket="/run/testudo/vsock.sock",
        guest_cid=3,
        guest_port=10000,
        network_policy=NetworkPolicy.model_validate(
            _network(phase="evaluation", purpose="declared_api")
        ),
    )
    assert profile.network == "none"
    assert profile.network_policy.purpose == "declared_api"


def test_non_none_backend_network_requires_policy() -> None:
    with pytest.raises(ValidationError, match="explicit network_policy"):
        IsolationProfile(network="bridge")


def test_docker_compatibility_rejects_unenforced_runtime_network_policy(tmp_path: Path) -> None:
    from testudo.runtime.docker import build_docker_argv

    profile = IsolationProfile(
        network="bridge",
        network_policy=NetworkPolicy.model_validate(
            _network(phase="evaluation", purpose="declared_api")
        ),
    )
    with pytest.raises(ValueError, match="cannot enforce network_policy"):
        build_docker_argv(
            workflow_path=tmp_path / "workflow.json",
            runs_dir=tmp_path / "runs",
            isolation=profile,
        )
