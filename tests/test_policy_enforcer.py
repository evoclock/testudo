# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address>]
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Pure deterministic tests for the host-boundary policy enforcer."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import ValidationError

from testudo.runtime.policy import NetworkPolicy, StoragePolicy, policy_digest
from testudo.runtime.policy_enforcer import (
    PolicyDenied,
    PolicyEnforcer,
    PolicyReceipt,
    WipeState,
    validate_policy,
)


def _network(**overrides: object) -> NetworkPolicy:
    value: dict[str, object] = {
        "phase": "evaluation",
        "purpose": "declared_api",
        "egress_hosts": ("api.example.com",),
        "egress_ports": (443,),
        "methods": ("GET", "POST"),
        "max_bytes": 10,
        "max_duration_seconds": 10,
    }
    value.update(overrides)
    return NetworkPolicy.model_validate(value)


def _enforcer(
    tmp_path: Path,
    *,
    clock: list[float] | None = None,
    wipe: Callable[[], object] | None = None,
) -> PolicyEnforcer:
    now = clock if clock is not None else [100.0]
    return PolicyEnforcer(
        StoragePolicy(
            phase="evaluation",
            cache="/cache/dependencies",
            cache_access="read_only",
        ),
        _network(),
        run_root=tmp_path,
        clock=lambda: now[0],
        wipe=wipe,
    )


def test_validation_is_separate_from_enforcement(tmp_path: Path) -> None:
    result = validate_policy(StoragePolicy(), NetworkPolicy(), run_root=tmp_path)
    assert result.valid is True
    assert result.policy_digest == policy_digest(StoragePolicy(), NetworkPolicy())
    invalid = validate_policy({"workspace": "/runs/../host"}, NetworkPolicy())
    assert invalid.valid is False
    assert invalid.errors


def test_declared_mounts_and_guest_paths_are_positive(tmp_path: Path) -> None:
    enforcer = _enforcer(tmp_path)
    launch = enforcer.before_launch()
    assert launch.allowed is True
    assert {mount.guest_path for mount in enforcer.mounts} == {
        "/runs",
        "/inputs",
        "/cache/dependencies",
    }
    assert enforcer.check_storage("/runs/result.json", operation="write").allowed
    assert enforcer.check_storage("/inputs/input.json", operation="read").allowed
    assert enforcer.check_mount(tmp_path / "inputs", "/inputs", "ro").allowed


@pytest.mark.parametrize("path", ["/runs/../host", "/runs/./host", "/runs//host", "relative"])
def test_guest_path_traversal_is_denied(tmp_path: Path, path: str) -> None:
    decision = _enforcer(tmp_path).check_storage(path, operation="read")
    assert decision.allowed is False
    assert (
        "path" in decision.reason
        or "canonical" in decision.reason
        or "traversal" in decision.reason
    )


def test_broad_or_mismatched_host_mount_is_denied(tmp_path: Path) -> None:
    enforcer = _enforcer(tmp_path)
    assert not enforcer.check_mount(tmp_path.parent, "/runs", "rw").allowed
    assert not enforcer.check_mount(tmp_path, "/", "rw").allowed
    assert not enforcer.check_mount(tmp_path / "inputs", "/inputs", "rw").allowed
    with pytest.raises(ValidationError, match="host mounts"):
        StoragePolicy(host_mounts=(str(tmp_path),))


def test_cache_mode_is_enforced_at_operation_boundary(tmp_path: Path) -> None:
    enforcer = _enforcer(tmp_path)
    assert enforcer.check_storage("/cache/dependencies/pkg.whl", operation="read").allowed
    denied = enforcer.check_storage("/cache/dependencies/pkg.whl", operation="write")
    assert denied.allowed is False
    assert "mode" in denied.reason
    writable = PolicyEnforcer(
        StoragePolicy(phase="provision", cache="/cache/dependencies", cache_access="read_write"),
        NetworkPolicy(
            phase="provision",
            purpose="dependency_fetch",
            egress_hosts=("pypi.org",),
            egress_ports=(443,),
            methods=("GET",),
            max_bytes=10,
            max_duration_seconds=10,
        ),
        run_root=tmp_path,
    )
    assert writable.check_storage("/cache/dependencies/pkg.whl", operation="write").allowed


def test_network_requires_exact_host_port_method_and_phase_purpose(tmp_path: Path) -> None:
    enforcer = _enforcer(tmp_path)
    assert enforcer.check_network(
        "api.example.com", 443, "GET", phase="evaluation", purpose="declared_api"
    ).allowed
    assert not enforcer.check_network("sub.api.example.com", 443, "GET").allowed
    assert not enforcer.check_network("api.example.com", 8443, "GET").allowed
    assert not enforcer.check_network("api.example.com", 443, "DELETE").allowed
    assert "phase" in enforcer.check_network("api.example.com", 443, "GET", phase="research").reason
    assert (
        "purpose"
        in enforcer.check_network("api.example.com", 443, "GET", purpose="resource_lookup").reason
    )


@pytest.mark.parametrize(
    "host", ["*.example.com", "https://api.example.com", "localhost", "127.0.0.1", "10.0.0.1"]
)
def test_network_policy_rejects_wildcard_url_and_unsafe_hosts(host: str) -> None:
    with pytest.raises(ValidationError):
        NetworkPolicy(
            phase="evaluation",
            purpose="declared_api",
            egress_hosts=(host,),
            egress_ports=(443,),
            methods=("GET",),
            max_bytes=10,
            max_duration_seconds=10,
        )


def test_network_byte_and_duration_limits_are_fail_closed(tmp_path: Path) -> None:
    clock = [100.0]
    enforcer = _enforcer(tmp_path, clock=clock)
    assert enforcer.check_network("api.example.com", 443, "GET", byte_count=6).allowed
    denied = enforcer.check_network("api.example.com", 443, "GET", byte_count=5)
    assert not denied.allowed
    assert "byte" in denied.reason
    clock[0] = 110.0
    expired = enforcer.check_network("api.example.com", 443, "GET", byte_count=1)
    assert not expired.allowed
    assert "expired" in expired.reason


def test_expiry_and_policy_digest_mismatch_are_denied(tmp_path: Path) -> None:
    clock = [100.0]
    enforcer = PolicyEnforcer(
        StoragePolicy(),
        _network(expires_at=105.0),
        run_root=tmp_path,
        clock=lambda: clock[0],
    )
    mismatch = enforcer.before_launch(policy_digest="0" * 64)
    assert not mismatch.allowed
    assert "mismatch" in mismatch.reason
    clock[0] = 105.0
    assert not enforcer.before_launch().allowed
    assert "expired" in enforcer.before_launch().reason


def test_launch_publication_receipt_is_digest_bound(tmp_path: Path) -> None:
    enforcer = _enforcer(tmp_path)
    assert not enforcer.before_publication().allowed
    launch = enforcer.before_launch()
    assert launch.receipt.verify(enforcer.policy_digest)
    assert not enforcer.before_publication(
        launch_receipt=launch.receipt, policy_digest="0" * 64
    ).allowed
    publication = enforcer.before_publication(launch_receipt=launch.receipt, byte_count=2)
    assert publication.allowed
    assert (
        PolicyReceipt.from_dict(publication.to_dict()).receipt_id == publication.receipt.receipt_id
    )


def test_require_raises_with_typed_denial(tmp_path: Path) -> None:
    with pytest.raises(PolicyDenied) as exc_info:
        _enforcer(tmp_path).require_network("api.example.com", 443, "DELETE")
    assert exc_info.value.decision.operation == "network.egress"
    assert exc_info.value.receipt.decision == "deny"


def test_wipe_state_and_enforcer_wipe_are_idempotent(tmp_path: Path) -> None:
    calls: list[str] = []
    state = WipeState(lambda: calls.append("wipe"))
    first = state.wipe()
    second = state.wipe()
    assert first == second
    assert calls == ["wipe"]
    enforcer = _enforcer(tmp_path, wipe=lambda: calls.append("enforcer-wipe"))
    assert enforcer.wipe() == enforcer.wipe()
    assert calls.count("enforcer-wipe") == 1
    assert not enforcer.check_storage("/runs/result.json", operation="read").allowed
