# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.runtime.isolation

Purpose: Pydantic model for a workflow's runtime isolation profile, plus the
loader that parses the ``isolation:`` block from ``workflow.json``. The model
is frozen and rejects unknown keys so a typo in the workflow fails loudly.

Inputs: a dict from the workflow's ``isolation:`` block, or ``None``.

Outputs: an ``IsolationProfile`` instance with sensible defaults
(testudo:0.1 image, 1 CPU, 2 GB memory, no network, read-only root with
tmpfs for /tmp, writable rollback layer at /runs).

Assumptions: the governed Runner selects a host microVM by default. The
profile's Docker-compatible image/resource fields are retained for the
explicit Docker compatibility backend; adding another backend is a deliberate
Runner change.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from testudo.runtime.policy import NetworkPolicy, StoragePolicy, policy_digest

IsolationPrimitive = Literal["docker", "microvm"]
NetworkMode = Literal["none", "bridge", "host"]
RootfsFormat = Literal["ext4", "squashfs"]


class IsolationProfile(BaseModel):
    """Runtime isolation profile from a workflow's ``isolation:`` block."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    primitive: IsolationPrimitive = "docker"
    image: str = "testudo:0.1"
    cpu: str = "1.0"
    memory: str = "2g"
    network: NetworkMode = "none"
    rollback: bool = True
    workdir: str = "/runs"
    read_only: bool = True
    storage_policy: StoragePolicy = Field(default_factory=StoragePolicy)
    network_policy: NetworkPolicy = Field(default_factory=NetworkPolicy)
    kernel_image: str | None = None
    rootfs: str | None = None
    rootfs_format: RootfsFormat | None = None
    vsock_socket: str | None = None
    guest_cid: int | None = None
    guest_port: int | None = None
    # Adapter-only guest session identity environment (native container mode).
    # Governed microVM profiles keep this unset; the model rejects any value
    # so the field can never smuggle a microVM-only override.
    run_id_env: str | None = Field(default=None, pattern=r"^TESTUDO_[A-Z0-9_]+$")

    @model_validator(mode="after")
    def validate_primitive_contract(self) -> IsolationProfile:
        """Require complete, networkless settings for governed microVMs."""
        microvm_fields = {
            "kernel_image": self.kernel_image,
            "rootfs": self.rootfs,
            "rootfs_format": self.rootfs_format,
            "vsock_socket": self.vsock_socket,
            "guest_cid": self.guest_cid,
            "guest_port": self.guest_port,
        }
        if self.primitive == "docker":
            configured = [name for name, value in microvm_fields.items() if value is not None]
            if configured:
                raise ValueError(
                    "microVM fields require primitive='microvm': " + ", ".join(configured)
                )
            if self.network != "none" and self.network_policy.purpose == "none":
                raise ValueError("non-none network requires an explicit network_policy")
            return self

        if self.run_id_env is not None:
            raise ValueError(
                "run_id_env is a native-container adapter setting, not a microVM field"
            )
        if self.network != "none":
            raise ValueError("microVM isolation requires network='none'")
        if not self.read_only:
            raise ValueError("microVM isolation requires read_only=True")
        missing = [name for name, value in microvm_fields.items() if value is None]
        if missing:
            raise ValueError("microVM isolation requires: " + ", ".join(missing))
        for name in ("kernel_image", "rootfs", "vsock_socket"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"microVM {name} must be a non-empty path")
        for name, minimum in (("guest_cid", 3), ("guest_port", 1)):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
                raise ValueError(f"microVM {name} is outside the allowed range")
            if value > 0xFFFFFFFF:
                raise ValueError(f"microVM {name} is outside the allowed range")
        return self

    @property
    def policy_digest(self) -> str:
        """Return the canonical binding for storage and network policy."""
        return policy_digest(self.storage_policy, self.network_policy)


def load_isolation(block: dict[str, object] | None) -> IsolationProfile:
    """Return an ``IsolationProfile`` from a workflow's ``isolation:`` block."""
    if not block:
        return IsolationProfile()
    return IsolationProfile.model_validate(block)
