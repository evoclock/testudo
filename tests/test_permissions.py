# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for ``testudo.permissions``: model, enforcement, and loader."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from testudo.permissions import (
    FilesystemPermissions,
    NetworkPermissions,
    PermissionDenied,
    Permissions,
    ProcessPermissions,
    check_filesystem_read,
    check_filesystem_write,
    check_network_egress,
    check_process_spawn,
    load_permissions,
    require_filesystem_read,
    require_filesystem_write,
    require_network_egress,
    require_process_spawn,
)

# ----------------------------------------------------------------------------
# Model defaults and immutability
# ----------------------------------------------------------------------------


def test_permissions_default_is_deny_by_default() -> None:
    perms = Permissions()
    assert perms.filesystem.read == ()
    assert perms.filesystem.write == ()
    assert perms.network.egress == ()
    assert perms.process.spawn is False


def test_permissions_model_is_frozen() -> None:
    perms = Permissions()
    with pytest.raises(ValidationError):
        perms.process = ProcessPermissions(spawn=True)  # type: ignore[misc]


# ----------------------------------------------------------------------------
# Filesystem checks
# ----------------------------------------------------------------------------


def test_check_filesystem_read_within_prefix(tmp_path: Path) -> None:
    perms = FilesystemPermissions(read=(str(tmp_path),))
    target = tmp_path / "subdir" / "file.txt"
    target.parent.mkdir()
    target.write_text("hello")
    assert check_filesystem_read(target, perms) is True


def test_check_filesystem_read_outside_prefix(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    perms = FilesystemPermissions(read=(str(allowed),))
    other = tmp_path / "other.txt"
    other.write_text("nope")
    assert check_filesystem_read(other, perms) is False


def test_check_filesystem_read_with_no_allowed_prefixes(tmp_path: Path) -> None:
    perms = FilesystemPermissions()
    assert check_filesystem_read(tmp_path / "anything", perms) is False


def test_require_filesystem_read_raises_with_metadata(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    perms = FilesystemPermissions(read=(str(allowed),))
    with pytest.raises(PermissionDenied) as info:
        require_filesystem_read(tmp_path / "elsewhere", perms)
    assert info.value.operation == "filesystem.read"
    assert "not within" in info.value.reason


def test_check_filesystem_write_within_prefix(tmp_path: Path) -> None:
    perms = FilesystemPermissions(write=(str(tmp_path),))
    assert check_filesystem_write(tmp_path / "out.txt", perms) is True


def test_require_filesystem_write_raises_when_denied(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    perms = FilesystemPermissions(write=(str(allowed),))
    with pytest.raises(PermissionDenied):
        require_filesystem_write(tmp_path / "other.txt", perms)


# ----------------------------------------------------------------------------
# Network checks
# ----------------------------------------------------------------------------


def test_check_network_egress_match() -> None:
    perms = NetworkPermissions(egress=("api.example.com",))
    assert check_network_egress("api.example.com", perms) is True


def test_check_network_egress_no_match() -> None:
    perms = NetworkPermissions(egress=("api.example.com",))
    assert check_network_egress("evil.com", perms) is False


def test_check_network_egress_default_deny() -> None:
    assert check_network_egress("api.example.com", NetworkPermissions()) is False


def test_require_network_egress_raises_with_metadata() -> None:
    perms = NetworkPermissions(egress=("api.example.com",))
    with pytest.raises(PermissionDenied) as info:
        require_network_egress("evil.com", perms)
    assert info.value.operation == "network.egress"
    assert info.value.target == "evil.com"


# ----------------------------------------------------------------------------
# Process checks
# ----------------------------------------------------------------------------


def test_check_process_spawn_default_deny() -> None:
    assert check_process_spawn(ProcessPermissions()) is False


def test_check_process_spawn_when_allowed() -> None:
    assert check_process_spawn(ProcessPermissions(spawn=True)) is True


def test_require_process_spawn_raises_by_default() -> None:
    with pytest.raises(PermissionDenied) as info:
        require_process_spawn(ProcessPermissions())
    assert info.value.operation == "process.spawn"


def test_require_process_spawn_passes_when_allowed() -> None:
    require_process_spawn(ProcessPermissions(spawn=True))  # no exception


# ----------------------------------------------------------------------------
# Loader
# ----------------------------------------------------------------------------


def test_load_permissions_returns_default_for_none() -> None:
    assert load_permissions(None) == Permissions()


def test_load_permissions_returns_default_for_empty_dict() -> None:
    assert load_permissions({}) == Permissions()


def test_load_permissions_from_full_workflow_block() -> None:
    block = {
        "filesystem": {"read": ["/inputs"], "write": ["/runs"]},
        "network": {"egress": ["api.example.com"]},
        "process": {"spawn": False},
    }
    perms = load_permissions(block)
    assert perms.filesystem.read == ("/inputs",)
    assert perms.filesystem.write == ("/runs",)
    assert perms.network.egress == ("api.example.com",)
    assert perms.process.spawn is False


def test_load_permissions_rejects_unknown_top_level_keys() -> None:
    with pytest.raises(ValidationError):
        load_permissions({"unknown_block": {}})


def test_permission_denied_message_includes_operation_and_target() -> None:
    err = PermissionDenied(
        operation="filesystem.read",
        target="/etc/passwd",
        reason="not allowed",
    )
    assert "filesystem.read" in str(err)
    assert "/etc/passwd" in str(err)
    assert err.operation == "filesystem.read"
    assert err.target == "/etc/passwd"
    assert err.reason == "not allowed"
