"""Testudo permissions package.

Purpose: declarative per-workflow permission model and the runtime enforcement
that goes with it. Deny-by-default for filesystem reads/writes, network egress,
and process spawning. Permissions are declared in the workflow's
``permissions:`` block and surfaced to the audit log on every decision.

Inputs: a permissions dict from the workflow specification.

Outputs: a ``Permissions`` object that the runtime and in-container subsystems
consult before any privileged operation.

Assumptions: permissions are static for the duration of a workflow run.
"""

from testudo.permissions.enforce import (
    PermissionDenied,
    check_filesystem_read,
    check_filesystem_write,
    check_network_egress,
    check_process_spawn,
    require_filesystem_read,
    require_filesystem_write,
    require_network_egress,
    require_process_spawn,
)
from testudo.permissions.loader import load_permissions
from testudo.permissions.model import (
    FilesystemPermissions,
    NetworkPermissions,
    Permissions,
    ProcessPermissions,
)

__all__ = [
    "FilesystemPermissions",
    "NetworkPermissions",
    "PermissionDenied",
    "Permissions",
    "ProcessPermissions",
    "check_filesystem_read",
    "check_filesystem_write",
    "check_network_egress",
    "check_process_spawn",
    "load_permissions",
    "require_filesystem_read",
    "require_filesystem_write",
    "require_network_egress",
    "require_process_spawn",
]
