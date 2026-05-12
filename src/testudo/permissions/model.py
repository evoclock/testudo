"""
Module: testudo.permissions.model

Purpose: Pydantic models for the declarative permission system. v0.1 covers
filesystem (read and write prefixes), network (egress host allow-list), and
process (spawn allow/deny). All permissions are deny-by-default; the empty
tuple defaults on each sub-model encode that posture explicitly.

Inputs: dictionaries from the workflow's ``permissions:`` block, or direct
constructor arguments.

Outputs: a ``Permissions`` instance with frozen sub-models.

Assumptions: permissions are static for the duration of a workflow run;
dynamic elevation is out of scope for v0.x.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class FilesystemPermissions(BaseModel):
    """Filesystem permissions: tuples of path prefixes for read and write."""

    model_config = ConfigDict(frozen=True)

    read: tuple[str, ...] = ()
    write: tuple[str, ...] = ()


class NetworkPermissions(BaseModel):
    """Network permissions: egress host allow-list (exact match in v0.1)."""

    model_config = ConfigDict(frozen=True)

    egress: tuple[str, ...] = ()


class ProcessPermissions(BaseModel):
    """Process permissions: deny-by-default spawning."""

    model_config = ConfigDict(frozen=True)

    spawn: bool = False


class Permissions(BaseModel):
    """Top-level permission model. Deny-by-default across all sub-models."""

    model_config = ConfigDict(frozen=True)

    filesystem: FilesystemPermissions = Field(default_factory=FilesystemPermissions)
    network: NetworkPermissions = Field(default_factory=NetworkPermissions)
    process: ProcessPermissions = Field(default_factory=ProcessPermissions)
