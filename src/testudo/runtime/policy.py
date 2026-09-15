# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address>]
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Declarative storage and network contracts for governed Testudo runs.

The models in this module perform *validation* only.  They reject malformed
or overly broad declarations, but they do not inspect a host filesystem,
install a firewall, or make a network request.  Host adapters must use
``testudo.runtime.policy_enforcer`` at each boundary to enforce these
contracts.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

StoragePhase = Literal["provision", "evaluation"]
CacheAccess = Literal["none", "read_only", "read_write"]
NetworkPhase = Literal["provision", "research", "evaluation"]
NetworkPurpose = Literal["none", "dependency_fetch", "resource_lookup", "declared_api"]

# An exact allow-list is intentionally finite.  These caps are validation
# bounds, not a substitute for the enforcer's accounting at run time.
_MAX_LIMIT = 2**63 - 1
_ALLOWED_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_UNSAFE_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home")


def _under(path: str, prefix: str) -> bool:
    """Return whether a lexical POSIX path is ``prefix`` or its descendant."""
    return path == prefix or path.startswith(prefix + "/")


def _validate_guest_path(path: str, *, field: str, prefix: str) -> str:
    """Validate a declared guest path without resolving it on the host.

    A host adapter must repeat the same lexical checks for operation paths;
    accepting a normalized host path here would make ``/runs/../host``
    indistinguishable from a safe path at the declaration boundary.
    """
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError(f"{field} must be an absolute guest path")
    if (
        not path
        or "\x00" in path
        or "\\" in path
        or any(ch.isspace() for ch in path)
        or "//" in path
        or (path.endswith("/") and path != "/")
    ):
        raise ValueError(f"{field} must be a canonical guest path")
    # Inspect the raw components; PurePosixPath normalizes ``.`` and ``..``.
    raw_parts = path.split("/")
    if any(part in {".", ".."} for part in raw_parts):
        raise ValueError(f"{field} contains path traversal")
    pure = PurePosixPath(path)
    if ".." in pure.parts or not _under(path, prefix):
        raise ValueError(f"{field} must remain under {prefix}")
    return path


def _validate_limit(value: int | None, *, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    if value <= 0 or value > _MAX_LIMIT:
        raise ValueError(f"{field} must be a positive {field} value")
    return value


def _validate_host(host: str) -> str:
    """Return a canonical exact host or reject unsafe/unrestricted targets."""
    if not isinstance(host, str) or not host or host != host.strip():
        raise ValueError("network egress hosts must be non-empty strings")
    if (
        "\x00" in host
        or "://" in host
        or "/" in host
        or "\\" in host
        or "*" in host
        or "?" in host
        or "#" in host
        or "@" in host
        or any(character.isspace() for character in host)
    ):
        raise ValueError("network egress hosts must be exact hostnames or IP addresses")

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        # Private, local, link-local, multicast, reserved and unspecified
        # addresses can reach the host/network control plane.  They are never
        # valid remote egress targets in a run policy.
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):
            raise ValueError("unsafe network egress host")
        return address.compressed

    canonical = host.rstrip(".").lower()
    if not canonical or canonical == "localhost" or canonical.endswith(_UNSAFE_HOST_SUFFIXES):
        raise ValueError("unsafe network egress host")
    labels = canonical.split(".")
    if not labels or any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError(f"invalid network egress host: {host!r}")
    # A one-label host is not an exact, externally scoped name and commonly
    # resolves through a host-local search domain.
    if len(labels) < 2:
        raise ValueError("network egress hosts must be fully qualified exact names")
    return canonical


class StoragePolicy(BaseModel):
    """Run-local storage exposed through declared guest paths only."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    phase: StoragePhase = "evaluation"
    host_scope: Literal["run_local"] = "run_local"
    workspace: str = "/runs"
    inputs: str = "/inputs"
    cache: str | None = None
    cache_access: CacheAccess = "none"
    # Kept as an explicit field so a workflow cannot silently smuggle an
    # adapter-specific host mount through an untyped extension.  The run-local
    # profile has no arbitrary host mounts; the enforcer derives mounts under
    # its supplied run root from workspace/inputs/cache.
    host_mounts: tuple[str, ...] = ()

    @field_validator("workspace")
    @classmethod
    def validate_workspace(cls, path: str) -> str:
        return _validate_guest_path(path, field="workspace", prefix="/runs")

    @field_validator("inputs")
    @classmethod
    def validate_inputs(cls, path: str) -> str:
        return _validate_guest_path(path, field="inputs", prefix="/inputs")

    @field_validator("cache")
    @classmethod
    def validate_cache(cls, path: str | None) -> str | None:
        if path is None:
            return None
        return _validate_guest_path(path, field="cache", prefix="/cache")

    @field_validator("host_mounts")
    @classmethod
    def reject_host_mounts(cls, mounts: tuple[str, ...]) -> tuple[str, ...]:
        if mounts:
            raise ValueError("arbitrary host mounts are not allowed by the run-local profile")
        return mounts

    @model_validator(mode="after")
    def validate_storage_boundary(self) -> StoragePolicy:
        if self.cache_access == "none" and self.cache is not None:
            raise ValueError("cache path requires cache_access other than 'none'")
        if self.cache_access != "none" and self.cache is None:
            raise ValueError("cache_access requires an explicit cache path")
        if self.phase == "evaluation" and self.cache_access == "read_write":
            raise ValueError("evaluation storage may use only a read-only cache")
        # Distinct top-level guest trees prevent overlapping mode declarations.
        paths = (self.workspace, self.inputs, self.cache)
        for index, left in enumerate(paths):
            if left is None:
                continue
            for right in paths[index + 1 :]:
                if right is not None and (_under(left, right) or _under(right, left)):
                    raise ValueError("storage guest paths must not overlap")
        return self


class NetworkPolicy(BaseModel):
    """Phase- and purpose-bound exact network egress intent."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    phase: NetworkPhase = "evaluation"
    purpose: NetworkPurpose = "none"
    egress_hosts: tuple[str, ...] = ()
    egress_ports: tuple[int, ...] = ()
    methods: tuple[str, ...] = ()
    max_bytes: int | None = None
    max_duration_seconds: int | None = None
    cache_write: bool = False
    # Optional absolute expiry.  Numeric epoch seconds are accepted for
    # deterministic adapters and normalized to UTC datetimes for the digest.
    expires_at: datetime | None = None

    @field_validator("egress_hosts")
    @classmethod
    def normalize_hosts(cls, hosts: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_validate_host(host) for host in hosts)
        if len(set(normalized)) != len(normalized):
            raise ValueError("network egress hosts must be unique")
        return normalized

    @field_validator("egress_ports")
    @classmethod
    def validate_ports(cls, ports: tuple[int, ...]) -> tuple[int, ...]:
        if any(isinstance(port, bool) or not isinstance(port, int) for port in ports):
            raise ValueError("network egress ports must be integers")
        if any(not 1 <= port <= 65535 for port in ports):
            raise ValueError("network egress ports must be between 1 and 65535")
        if len(set(ports)) != len(ports):
            raise ValueError("network egress ports must be unique")
        return ports

    @field_validator("methods")
    @classmethod
    def normalize_methods(cls, methods: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(
            method.upper() if isinstance(method, str) else method for method in methods
        )
        if any(
            not isinstance(method, str) or method not in _ALLOWED_METHODS for method in normalized
        ):
            raise ValueError("network methods contain an unsupported HTTP method")
        if len(set(normalized)) != len(normalized):
            raise ValueError("network methods must be unique")
        return normalized

    @field_validator("max_bytes")
    @classmethod
    def validate_max_bytes(cls, value: int | None) -> int | None:
        return _validate_limit(value, field="max_bytes")

    @field_validator("max_duration_seconds")
    @classmethod
    def validate_max_duration(cls, value: int | None) -> int | None:
        return _validate_limit(value, field="max_duration_seconds")

    @field_validator("cache_write", mode="before")
    @classmethod
    def validate_cache_write(cls, value: object) -> object:
        if not isinstance(value, bool):
            raise ValueError("cache_write must be a boolean")
        return value

    @field_validator("expires_at", mode="before")
    @classmethod
    def normalize_expiry(cls, value: object) -> object:
        if isinstance(value, bool):
            raise ValueError("expires_at must be an absolute UTC timestamp")
        if isinstance(value, (int, float)):
            if value <= 0:
                raise ValueError("expires_at must be a positive timestamp")
            return datetime.fromtimestamp(value, tz=UTC)
        return value

    @model_validator(mode="after")
    def validate_phase_purpose(self) -> NetworkPolicy:
        if self.purpose == "none":
            if self.egress_hosts or self.egress_ports or self.methods:
                raise ValueError("purpose='none' cannot carry an egress allow-list")
            if self.max_bytes is not None or self.max_duration_seconds is not None:
                raise ValueError("purpose='none' cannot carry network limits")
            if self.cache_write:
                raise ValueError("purpose='none' cannot write a dependency cache")
            return self

        if not self.egress_hosts or not self.egress_ports or not self.methods:
            raise ValueError("network access requires hosts, ports and methods")
        if self.max_bytes is None:
            raise ValueError("network access requires a finite max_bytes")
        if self.max_duration_seconds is None:
            raise ValueError("network access requires a finite max_duration_seconds")
        if self.cache_write and not (
            self.purpose == "dependency_fetch" and self.phase == "provision"
        ):
            raise ValueError("only provision dependency_fetch may write an evaluation cache")
        expected_phase: dict[str, str] = {
            "dependency_fetch": "provision",
            "resource_lookup": "research",
            "declared_api": "evaluation",
        }
        if self.phase != expected_phase[self.purpose]:
            if self.purpose == "resource_lookup" and self.phase == "evaluation":
                raise ValueError("resource_lookup is forbidden during evaluation")
            raise ValueError(
                f"{self.purpose} is permitted only during {expected_phase[self.purpose]}"
            )
        return self


def policy_digest(storage: StoragePolicy, network: NetworkPolicy) -> str:
    """Return the canonical SHA-256 binding for both runtime policies."""
    payload = {
        "network": network.model_dump(mode="json"),
        "storage": storage.model_dump(mode="json"),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def is_policy_digest(value: object) -> bool:
    """Return whether ``value`` is a lowercase SHA-256 policy digest."""
    return isinstance(value, str) and _HEX_DIGEST.fullmatch(value) is not None


__all__ = [
    "CacheAccess",
    "NetworkPhase",
    "NetworkPolicy",
    "NetworkPurpose",
    "StoragePhase",
    "StoragePolicy",
    "is_policy_digest",
    "policy_digest",
]
