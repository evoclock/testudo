# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.permissions.enforce

Purpose: runtime enforcement of declarative permissions. Pure predicate
functions plus thin ``require_*`` helpers that raise ``PermissionDenied`` so
callers can ``try``/``except`` cleanly. Decisions are emitted to the audit log
by the calling layer (the orchestrator), not by this module, so this module
stays a pure predicate layer testable in isolation.

Inputs: a path, host, or operation argument plus the relevant permissions
sub-model.

Outputs: ``True``/``False`` from the ``check_*`` functions; ``None`` from the
``require_*`` helpers, with ``PermissionDenied`` raised on denial.

Assumptions: paths are checked against their resolved real-paths via
``Path.resolve()``. v0.1 does not follow symlinks across permission boundaries
(a resolved path that escapes the allowed prefix tree is denied).

Failure modes: ``PermissionDenied`` carries ``operation``, ``target``, and
``reason`` attributes so the caller's audit record is complete.
"""

from __future__ import annotations

from pathlib import Path

from testudo.permissions.model import (
    FilesystemPermissions,
    NetworkPermissions,
    ProcessPermissions,
)


class PermissionDenied(Exception):
    """Raised when an operation is denied by the workflow's permissions."""

    def __init__(self, *, operation: str, target: str, reason: str) -> None:
        super().__init__(f"PermissionDenied: {operation} {target!r} ({reason})")
        self.operation = operation
        self.target = target
        self.reason = reason


def _is_within(target: Path, prefix: Path) -> bool:
    """Return True iff target's resolved path is the same as or under prefix."""
    return target.is_relative_to(prefix)


# --- filesystem --------------------------------------------------------------


def check_filesystem_read(path: str | Path, perms: FilesystemPermissions) -> bool:
    """Return True iff ``path`` resolves within any allowed read prefix."""
    target = Path(path).resolve()
    return any(_is_within(target, Path(p).resolve()) for p in perms.read)


def require_filesystem_read(path: str | Path, perms: FilesystemPermissions) -> None:
    """Raise ``PermissionDenied`` if filesystem-read of ``path`` is not permitted."""
    if not check_filesystem_read(path, perms):
        raise PermissionDenied(
            operation="filesystem.read",
            target=str(path),
            reason="path not within any allowed read prefix",
        )


def check_filesystem_write(path: str | Path, perms: FilesystemPermissions) -> bool:
    """Return True iff ``path`` resolves within any allowed write prefix."""
    target = Path(path).resolve()
    return any(_is_within(target, Path(p).resolve()) for p in perms.write)


def require_filesystem_write(path: str | Path, perms: FilesystemPermissions) -> None:
    """Raise ``PermissionDenied`` if filesystem-write of ``path`` is not permitted."""
    if not check_filesystem_write(path, perms):
        raise PermissionDenied(
            operation="filesystem.write",
            target=str(path),
            reason="path not within any allowed write prefix",
        )


# --- network -----------------------------------------------------------------


def check_network_egress(host: str, perms: NetworkPermissions) -> bool:
    """Return True iff ``host`` matches an entry in the egress allow-list.

    v0.1 is exact-match only; v0.2 will add subdomain matching.
    """
    return host in perms.egress


def require_network_egress(host: str, perms: NetworkPermissions) -> None:
    """Raise ``PermissionDenied`` if network egress to ``host`` is not permitted."""
    if not check_network_egress(host, perms):
        raise PermissionDenied(
            operation="network.egress",
            target=host,
            reason="host not in egress allow-list",
        )


# --- process -----------------------------------------------------------------


def check_process_spawn(perms: ProcessPermissions) -> bool:
    """Return True iff process spawning is allowed."""
    return perms.spawn


def require_process_spawn(perms: ProcessPermissions) -> None:
    """Raise ``PermissionDenied`` if process spawning is not permitted."""
    if not check_process_spawn(perms):
        raise PermissionDenied(
            operation="process.spawn",
            target="",
            reason="process spawning denied by workflow permissions",
        )
