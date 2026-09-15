# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address>]
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Deterministic host-boundary enforcement for runtime policies.

``testudo.runtime.policy`` validates declarations.  This module is the
separate enforcement layer adapters call immediately before launch and again
before publication.  It never opens a socket, starts a VM, mounts a host
path, or writes a receipt: adapters perform those effects only after an
allowed decision and retain the typed receipt as evidence.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Literal, cast

from pydantic import ValidationError

from testudo.runtime.policy import (
    CacheAccess,
    NetworkPolicy,
    StoragePolicy,
    _validate_host,
    is_policy_digest,
)
from testudo.runtime.policy import (
    policy_digest as compute_policy_digest,
)

DecisionKind = Literal["allow", "deny"]
StorageOperation = Literal["read", "write", "mount"]

_ZERO_DIGEST = "0" * 64
_RECEIPT_SCHEMA = "testudo.runtime.policy.receipt.v1"


class PolicyValidationError(ValueError):
    """Raised when a policy cannot be validated before enforcement."""


class PolicyDenied(PermissionError):
    """Raised by ``require_*`` helpers when a typed decision denies access."""

    def __init__(self, decision: PolicyDecision) -> None:
        self.decision = decision
        self.receipt = decision.receipt
        self.operation = decision.operation
        self.reason = decision.reason
        super().__init__(f"policy denied: {decision.operation} ({decision.reason})")


class PolicyBindingError(PolicyDenied):
    """Compatibility name for a digest-bound policy denial."""


def _canonical(value: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("policy receipt details must be canonical JSON") from exc


def _sha256(value: Mapping[str, object]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _as_timestamp(value: float | int | datetime | None, *, field_name: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError(f"{field_name} must include a timezone")
        result = value.astimezone(UTC).timestamp()
    elif isinstance(value, bool) or not isinstance(value, (float, int)):
        raise ValueError(f"{field_name} must be a finite timestamp")
    else:
        result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise ValueError(f"{field_name} must be a finite positive timestamp")
    return result


def _validate_clock(clock: Callable[[], float]) -> float:
    value = clock()
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError("clock must return a finite number")
    return float(value)


def _under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


def _safe_guest_path(path: str | Path) -> str:
    value = str(path)
    if not value.startswith("/"):
        raise ValueError("guest path must be absolute")
    if "\x00" in value or "\\" in value or "//" in value or (value.endswith("/") and value != "/"):
        raise ValueError("guest path is not canonical")
    parts = value.split("/")
    if any(part in {".", ".."} for part in parts):
        raise ValueError("guest path contains path traversal")
    return value


def _safe_host_path(path: str | Path, *, run_root: Path) -> Path:
    raw = str(path)
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise ValueError("host path must be absolute")
    if "\x00" in raw or "\\" in raw:
        raise ValueError("host path is not canonical")
    raw_parts = PurePosixPath(raw).parts
    if any(part in {".", ".."} for part in raw_parts):
        raise ValueError("host path contains path traversal")
    resolved_root = run_root.resolve(strict=False)
    resolved_candidate = candidate.resolve(strict=False)
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError("host path is outside run-local root") from exc
    return resolved_candidate


@dataclass(frozen=True, slots=True)
class PolicyReceipt:
    """Immutable hash-bound evidence for one enforcement decision."""

    operation: str
    decision: DecisionKind
    policy_digest: str
    target: str
    reason: str
    sequence: int
    issued_at: float
    phase: str
    purpose: str
    details: Mapping[str, object] = field(default_factory=dict)
    receipt_id: str = field(init=False)
    schema: str = field(init=False, default=_RECEIPT_SCHEMA)

    def __post_init__(self) -> None:
        if (
            any(
                not isinstance(value, str)
                for value in (
                    self.operation,
                    self.policy_digest,
                    self.target,
                    self.reason,
                    self.phase,
                    self.purpose,
                )
            )
            or not self.operation
        ):
            raise ValueError("policy receipt operation and identity fields are required")
        if self.decision not in {"allow", "deny"}:
            raise ValueError("policy receipt decision is invalid")
        if not is_policy_digest(self.policy_digest):
            raise ValueError("policy receipt must carry a SHA-256 policy digest")
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 0
            or isinstance(self.issued_at, bool)
            or not isinstance(self.issued_at, (int, float))
            or not math.isfinite(self.issued_at)
        ):
            raise ValueError("policy receipt sequence/time is invalid")
        details = dict(self.details)
        if any(not isinstance(key, str) for key in details):
            raise ValueError("policy receipt detail keys must be strings")
        # Validate once at construction so a receipt can always be serialized
        # and independently verified by an adapter.
        payload = self._payload(details)
        _canonical(payload)
        object.__setattr__(self, "details", MappingProxyType(details))
        object.__setattr__(self, "receipt_id", _sha256(payload))

    def _payload(self, details: Mapping[str, object] | None = None) -> dict[str, object]:
        return {
            "schema": self.schema,
            "operation": self.operation,
            "decision": self.decision,
            "policy_digest": self.policy_digest,
            "target": self.target,
            "reason": self.reason,
            "sequence": self.sequence,
            "issued_at": self.issued_at,
            "phase": self.phase,
            "purpose": self.purpose,
            "details": dict(self.details if details is None else details),
        }

    @property
    def digest(self) -> str:
        """Alias used by adapters that call the binding a digest."""
        return self.policy_digest

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    @property
    def denied(self) -> bool:
        return not self.allowed

    def verify(self, expected_digest: str) -> bool:
        """Verify both the receipt hash and its policy binding."""
        if not is_policy_digest(expected_digest):
            return False
        return hmac.compare_digest(self.policy_digest, expected_digest) and hmac.compare_digest(
            self.receipt_id, _sha256(self._payload())
        )

    def to_dict(self) -> dict[str, object]:
        payload = self._payload()
        payload["receipt_id"] = self.receipt_id
        return payload

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> PolicyReceipt:
        """Parse and verify a serialized receipt without trusting its id."""
        required = (
            "schema",
            "operation",
            "decision",
            "policy_digest",
            "target",
            "reason",
            "sequence",
            "issued_at",
            "phase",
            "purpose",
            "details",
            "receipt_id",
        )
        if any(name not in value for name in required):
            raise ValueError("policy receipt is missing required fields")
        if value["schema"] != _RECEIPT_SCHEMA:
            raise ValueError("unsupported policy receipt schema")
        details = value["details"]
        if not isinstance(details, Mapping):
            raise ValueError("policy receipt details must be a map")
        receipt = cls(
            operation=cast(str, value["operation"]),
            decision=cast(DecisionKind, value["decision"]),
            policy_digest=cast(str, value["policy_digest"]),
            target=cast(str, value["target"]),
            reason=cast(str, value["reason"]),
            sequence=cast(int, value["sequence"]),
            issued_at=cast(float, value["issued_at"]),
            phase=cast(str, value["phase"]),
            purpose=cast(str, value["purpose"]),
            details=dict(details),
        )
        if value["receipt_id"] != receipt.receipt_id:
            raise ValueError("policy receipt id mismatch")
        return receipt


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Typed allow/deny result paired with an auditable receipt."""

    operation: str
    allowed: bool
    reason: str
    receipt: PolicyReceipt
    policy_digest: str
    target: str = ""
    phase: str = ""
    purpose: str = ""

    @property
    def decision(self) -> DecisionKind:
        return "allow" if self.allowed else "deny"

    @property
    def allow(self) -> bool:
        return self.allowed

    @property
    def denied(self) -> bool:
        return not self.allowed

    @property
    def ok(self) -> bool:
        return self.allowed

    @property
    def digest(self) -> str:
        return self.policy_digest

    def require(self) -> PolicyReceipt:
        if not self.allowed:
            if "digest" in self.reason or "binding" in self.reason:
                raise PolicyBindingError(self)
            raise PolicyDenied(self)
        return self.receipt

    def to_dict(self) -> dict[str, object]:
        return self.receipt.to_dict()


@dataclass(frozen=True, slots=True)
class PolicyValidation:
    """Result of declaration validation, kept distinct from enforcement."""

    valid: bool
    policy_digest: str | None
    errors: tuple[str, ...] = ()
    storage_policy: StoragePolicy | None = None
    network_policy: NetworkPolicy | None = None

    @property
    def ok(self) -> bool:
        return self.valid

    @property
    def allowed(self) -> bool:
        return self.valid

    @property
    def digest(self) -> str | None:
        return self.policy_digest

    def require(self) -> PolicyValidation:
        if not self.valid:
            raise PolicyValidationError("; ".join(self.errors) or "runtime policy is invalid")
        return self


# A shorter name is convenient to callers and preserves the validation/
# enforcement distinction in the type name above.
ValidationResult = PolicyValidation


@dataclass(frozen=True, slots=True)
class MountBinding:
    """A run-local host source and its declared guest destination."""

    host_path: str
    guest_path: str
    mode: Literal["ro", "rw"]

    @property
    def read_only(self) -> bool:
        return self.mode == "ro"

    def to_dict(self) -> dict[str, str]:
        return {"host_path": self.host_path, "guest_path": self.guest_path, "mode": self.mode}


@dataclass(frozen=True, slots=True)
class NetworkRequest:
    """A normalized network request supplied to an adapter boundary."""

    host: str
    port: int
    method: str
    byte_count: int = 0
    phase: str | None = None
    purpose: str | None = None

    @property
    def bytes(self) -> int:
        return self.byte_count


class WipeState:
    """Thread-safe, idempotent host wipe state and receipt producer."""

    def __init__(
        self,
        wipe: Callable[[], object] | None = None,
        *,
        callback: Callable[[], object] | None = None,
        wipe_callback: Callable[[], object] | None = None,
    ) -> None:
        callbacks = [value for value in (wipe, callback, wipe_callback) if value is not None]
        if len(callbacks) > 1:
            raise ValueError("provide only one wipe callback")
        self._wipe = callbacks[0] if callbacks else None
        self._lock = threading.Lock()
        self._wiped = False
        self._receipt: PolicyReceipt | None = None

    @property
    def wiped(self) -> bool:
        return self._wiped

    @property
    def is_wiped(self) -> bool:
        return self._wiped

    @property
    def receipt(self) -> PolicyReceipt | None:
        return self._receipt

    def mark_wiped(self) -> None:
        """Record a prior adapter wipe without invoking a callback."""
        with self._lock:
            self._wiped = True
            if self._receipt is None:
                self._receipt = PolicyReceipt(
                    operation="wipe",
                    decision="allow",
                    policy_digest=_ZERO_DIGEST,
                    target="run-local-state",
                    reason="already_wiped",
                    sequence=0,
                    issued_at=0.0,
                    phase="",
                    purpose="none",
                )

    def wipe(
        self,
        callback: Callable[[], object] | None = None,
        *,
        reason: str = "policy_wipe",
        policy_digest: str = _ZERO_DIGEST,
        issued_at: float = 0.0,
    ) -> PolicyReceipt:
        if callback is not None and self._wipe is not None and callback is not self._wipe:
            raise ValueError("wipe callback is already configured")
        if callback is not None and self._wipe is None:
            self._wipe = callback
        if not is_policy_digest(policy_digest):
            raise ValueError("wipe receipt requires a policy digest")
        with self._lock:
            if self._receipt is not None:
                return self._receipt
            # Set state before invoking an untrusted adapter callback.  A
            # callback failure therefore remains fail-closed and cannot cause
            # a second destructive call on retry.
            self._wiped = True
            receipt = PolicyReceipt(
                operation="wipe",
                decision="allow",
                policy_digest=policy_digest,
                target="run-local-state",
                reason=reason,
                sequence=0,
                issued_at=issued_at,
                phase="",
                purpose="none",
            )
            self._receipt = receipt
            if self._wipe is not None:
                self._wipe()
            return receipt

    wipe_once = wipe


def _coerce_policies(
    storage_policy: StoragePolicy | Mapping[str, object],
    network_policy: NetworkPolicy | Mapping[str, object],
) -> tuple[StoragePolicy, NetworkPolicy]:
    try:
        storage = (
            storage_policy
            if isinstance(storage_policy, StoragePolicy)
            else StoragePolicy.model_validate(storage_policy)
        )
        network = (
            network_policy
            if isinstance(network_policy, NetworkPolicy)
            else NetworkPolicy.model_validate(network_policy)
        )
    except (ValidationError, TypeError, ValueError) as exc:
        raise PolicyValidationError(str(exc)) from exc
    return storage, network


def _validate_run_root(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    raw = str(value)
    path = Path(raw)
    if not path.is_absolute():
        raise PolicyValidationError("run_root must be an absolute host path")
    if "\x00" in raw or "\\" in raw:
        raise PolicyValidationError("run_root is not a canonical host path")
    if any(part in {".", ".."} for part in PurePosixPath(raw).parts):
        raise PolicyValidationError("run_root contains path traversal")
    if path.is_symlink():
        raise PolicyValidationError("run_root must not be a symlink")
    return path.resolve(strict=False)


def validate_policy(
    storage_policy: StoragePolicy | Mapping[str, object],
    network_policy: NetworkPolicy | Mapping[str, object],
    *,
    run_root: str | Path | None = None,
) -> PolicyValidation:
    """Validate declarations without authorizing or performing an operation."""
    try:
        storage, network = _coerce_policies(storage_policy, network_policy)
        root = _validate_run_root(run_root)
        if storage.host_scope != "run_local" or storage.host_mounts:
            raise PolicyValidationError("storage must use the run_local scope without host mounts")
        if root is not None and root == Path("/"):
            raise PolicyValidationError("run_root must not be the host root")
        digest = compute_policy_digest(storage, network)
    except (PolicyValidationError, ValueError, TypeError) as exc:
        return PolicyValidation(False, None, (str(exc),))
    return PolicyValidation(True, digest, (), storage, network)


validate_policies = validate_policy


class PolicyEnforcer:
    """Fail-closed storage/network boundary for one run.

    The object is intentionally side-effect free apart from in-memory byte,
    sequence and wipe state.  Injecting ``clock`` makes expiry and quota tests
    deterministic and lets a host adapter use its monotonic clock.
    """

    def __init__(
        self,
        storage_policy: StoragePolicy | Mapping[str, object],
        network_policy: NetworkPolicy | Mapping[str, object],
        *,
        run_root: str | Path | None = None,
        expected_digest: str | None = None,
        policy_digest: str | None = None,
        clock: Callable[[], float] | None = None,
        now: Callable[[], float] | None = None,
        expires_at: float | int | datetime | None = None,
        wipe: Callable[[], object] | None = None,
        wipe_callback: Callable[[], object] | None = None,
        wipe_vm: Callable[[], object] | None = None,
        run_id: str = "",
    ) -> None:
        if (
            expected_digest is not None
            and policy_digest is not None
            and expected_digest != policy_digest
        ):
            raise PolicyValidationError("expected_digest and policy_digest disagree")
        self.storage_policy, self.network_policy = _coerce_policies(storage_policy, network_policy)
        self.run_root = _validate_run_root(run_root)
        if self.run_root == Path("/"):
            raise PolicyValidationError("run_root must not be the host root")
        self.policy_digest = compute_policy_digest(self.storage_policy, self.network_policy)
        supplied_digest = expected_digest if expected_digest is not None else policy_digest
        self.expected_digest = (
            supplied_digest if supplied_digest is not None else self.policy_digest
        )
        self._binding_error: str | None = None
        if not is_policy_digest(self.expected_digest):
            self._binding_error = "policy digest is malformed"
        elif not hmac.compare_digest(self.expected_digest, self.policy_digest):
            self._binding_error = "policy digest does not match declared policy"
        self._clock = clock if clock is not None else (now if now is not None else time.monotonic)
        self._started_at = _validate_clock(self._clock)
        policy_expiry = self.network_policy.expires_at
        self._expires_at = _as_timestamp(expires_at, field_name="expires_at")
        if self._expires_at is None and policy_expiry is not None:
            self._expires_at = _as_timestamp(policy_expiry, field_name="policy expires_at")
        self._network_bytes = 0
        self._sequence = 0
        self._launch_receipt: PolicyReceipt | None = None
        self._published = False
        callbacks = [value for value in (wipe, wipe_callback, wipe_vm) if value is not None]
        if len(callbacks) > 1:
            raise PolicyValidationError("wipe callbacks disagree")
        self._wipe_state = WipeState(callbacks[0] if callbacks else None)
        self.run_id = run_id

    @classmethod
    def from_policies(cls, *args: object, **kwargs: object) -> PolicyEnforcer:
        return cls(*cast(Any, args), **cast(Any, kwargs))

    @property
    def digest(self) -> str:
        return self.policy_digest

    @property
    def network_bytes(self) -> int:
        return self._network_bytes

    @property
    def remaining_network_bytes(self) -> int | None:
        limit = self.network_policy.max_bytes
        return None if limit is None else max(0, limit - self._network_bytes)

    @property
    def wipe_state(self) -> WipeState:
        return self._wipe_state

    @property
    def wiped(self) -> bool:
        return self._wipe_state.wiped

    @property
    def launch_receipt(self) -> PolicyReceipt | None:
        return self._launch_receipt

    @property
    def mounts(self) -> tuple[MountBinding, ...]:
        """Return the only host mounts this run-local profile may expose."""
        if self.run_root is None:
            return ()
        mounts: list[MountBinding] = [
            MountBinding(str(self.run_root), self.storage_policy.workspace, "rw"),
            MountBinding(str(self.run_root / "inputs"), self.storage_policy.inputs, "ro"),
        ]
        if self.storage_policy.cache is not None:
            mode: Literal["ro", "rw"] = (
                "rw" if self.storage_policy.cache_access == "read_write" else "ro"
            )
            mounts.append(
                MountBinding(str(self.run_root / "cache"), self.storage_policy.cache, mode)
            )
        return tuple(mounts)

    @property
    def mount_plan(self) -> tuple[MountBinding, ...]:
        return self.mounts

    @property
    def declared_mounts(self) -> tuple[MountBinding, ...]:
        return self.mounts

    def build_mounts(self) -> tuple[MountBinding, ...]:
        return self.mounts

    def _next(self) -> int:
        sequence = self._sequence
        self._sequence += 1
        return sequence

    def _decision(
        self,
        operation: str,
        allowed: bool,
        reason: str,
        *,
        target: str = "",
        phase: str | None = None,
        purpose: str | None = None,
        details: Mapping[str, object] | None = None,
    ) -> PolicyDecision:
        receipt = PolicyReceipt(
            operation=operation,
            decision="allow" if allowed else "deny",
            policy_digest=self.policy_digest,
            target=target,
            reason=reason,
            sequence=self._next(),
            issued_at=_validate_clock(self._clock),
            phase=phase if phase is not None else self.network_policy.phase,
            purpose=purpose if purpose is not None else self.network_policy.purpose,
            details={} if details is None else details,
        )
        return PolicyDecision(
            operation=operation,
            allowed=allowed,
            reason=reason,
            receipt=receipt,
            policy_digest=self.policy_digest,
            target=target,
            phase=receipt.phase,
            purpose=receipt.purpose,
        )

    def _common_denial(
        self, candidate_digest: str | None, *, require_digest: bool = False
    ) -> str | None:
        if self._binding_error is not None:
            return self._binding_error
        if require_digest and candidate_digest is None:
            return "policy digest binding is required"
        if candidate_digest is not None and (
            not is_policy_digest(candidate_digest)
            or not hmac.compare_digest(candidate_digest, self.policy_digest)
        ):
            return "policy digest mismatch"
        if self.wiped:
            return "run state has been wiped"
        now = _validate_clock(self._clock)
        if self._expires_at is not None and now >= self._expires_at:
            return "policy expired"
        return None

    def _network_expiry_reason(self) -> str | None:
        if self.network_policy.max_duration_seconds is None:
            return None
        now = _validate_clock(self._clock)
        if now - self._started_at >= self.network_policy.max_duration_seconds:
            return "network policy duration expired"
        return None

    def _mount_for_guest(self, guest_path: str) -> tuple[str, CacheAccess] | None:
        candidates: list[tuple[str, CacheAccess]] = [
            (self.storage_policy.workspace, "read_write"),
            (self.storage_policy.inputs, "read_only"),
        ]
        if self.storage_policy.cache is not None:
            candidates.append((self.storage_policy.cache, self.storage_policy.cache_access))
        for prefix, mode in candidates:
            if _under(guest_path, prefix):
                return prefix, mode
        return None

    def _expected_host_path(self, guest_path: str, prefix: str) -> Path | None:
        if self.run_root is None:
            return None
        suffix = guest_path[len(prefix) :].lstrip("/")
        base: Path
        if prefix == self.storage_policy.workspace:
            base = self.run_root
        elif prefix == self.storage_policy.inputs:
            base = self.run_root / "inputs"
        elif self.storage_policy.cache is not None and prefix == self.storage_policy.cache:
            base = self.run_root / "cache"
        else:
            return None
        return (base / suffix).resolve(strict=False)

    def check_mount(
        self,
        host_path: str | Path,
        guest_path: str | Path,
        mode: str,
        *,
        policy_digest: str | None = None,
    ) -> PolicyDecision:
        """Authorize one adapter mount without touching the host filesystem."""
        target = f"{host_path}:{guest_path}:{mode}"
        common = self._common_denial(policy_digest)
        if common is not None:
            return self._decision("mount", False, common, target=target)
        if self.run_root is None:
            return self._decision(
                "mount", False, "run_root is required for host mounts", target=target
            )
        try:
            guest = _safe_guest_path(guest_path)
            host = _safe_host_path(host_path, run_root=self.run_root)
        except ValueError as exc:
            return self._decision("mount", False, str(exc), target=target)
        selected = self._mount_for_guest(guest)
        if selected is None:
            return self._decision(
                "mount", False, "guest mount is not a declared run-local path", target=target
            )
        prefix, access = selected
        if guest != prefix:
            return self._decision(
                "mount", False, "mount must target the declared guest root", target=target
            )
        expected_host = self._expected_host_path(guest, prefix)
        if expected_host is None or host != expected_host:
            return self._decision(
                "mount", False, "host mount is not bound to the declared guest path", target=target
            )
        expected_mode = "rw" if access == "read_write" else "ro"
        if mode != expected_mode:
            return self._decision(
                "mount", False, "mount mode exceeds declared cache/storage mode", target=target
            )
        # Mounting a parent of the run root is impossible after _safe_host_path;
        # the exact mapping above also prevents a sibling or broad mount.
        return self._decision(
            "mount",
            True,
            "mount is declared and run-local",
            target=target,
            details={"host_path": str(host), "guest_path": guest, "mode": mode},
        )

    authorize_mount = check_mount
    enforce_mount = check_mount

    def check_storage(
        self,
        guest_path: str | Path,
        *,
        operation: str = "read",
        host_path: str | Path | None = None,
        policy_digest: str | None = None,
    ) -> PolicyDecision:
        """Authorize read/write access to a declared guest path."""
        target = str(guest_path)
        common = self._common_denial(policy_digest)
        if common is not None:
            return self._decision("storage." + operation, False, common, target=target)
        try:
            guest = _safe_guest_path(guest_path)
        except ValueError as exc:
            return self._decision("storage." + operation, False, str(exc), target=target)
        if operation not in {"read", "write", "mount"}:
            return self._decision(
                "storage." + operation, False, "unknown storage operation", target=target
            )
        selected = self._mount_for_guest(guest)
        if selected is None:
            return self._decision(
                "storage." + operation,
                False,
                "guest path is outside declared run-local paths",
                target=target,
            )
        prefix, access = selected
        if operation == "write" and access != "read_write":
            return self._decision(
                "storage.write", False, "write exceeds declared cache/storage mode", target=target
            )
        if operation == "mount":
            if guest != prefix:
                return self._decision(
                    "storage.mount",
                    False,
                    "mount must target the declared guest root",
                    target=target,
                )
            return self.check_mount(
                host_path if host_path is not None else "",
                guest,
                "rw" if access == "read_write" else "ro",
                policy_digest=policy_digest,
            )
        if host_path is not None:
            if self.run_root is None:
                return self._decision(
                    "storage." + operation,
                    False,
                    "run_root is required for host paths",
                    target=target,
                )
            try:
                actual_host = _safe_host_path(host_path, run_root=self.run_root)
            except ValueError as exc:
                return self._decision("storage." + operation, False, str(exc), target=target)
            expected_host = self._expected_host_path(guest, prefix)
            if expected_host is None or actual_host != expected_host:
                return self._decision(
                    "storage." + operation,
                    False,
                    "host path is not bound to guest path",
                    target=target,
                )
        return self._decision(
            "storage." + operation,
            True,
            "path is declared and within run-local scope",
            target=target,
            details={"guest_path": guest, "operation": operation, "mode": access},
        )

    def check_storage_path(
        self,
        guest_path: str | Path,
        *,
        write: bool = False,
        operation: str | None = None,
        host_path: str | Path | None = None,
        policy_digest: str | None = None,
    ) -> PolicyDecision:
        selected_operation = operation if operation is not None else ("write" if write else "read")
        return self.check_storage(
            guest_path,
            operation=selected_operation,
            host_path=host_path,
            policy_digest=policy_digest,
        )

    authorize_storage = check_storage
    enforce_storage = check_storage
    check_path = check_storage_path

    def require_storage(self, guest_path: str | Path, **kwargs: object) -> PolicyReceipt:
        decision = self.check_storage(guest_path, **cast(Any, kwargs))
        return decision.require()

    def require_storage_path(self, guest_path: str | Path, **kwargs: object) -> PolicyReceipt:
        decision = self.check_storage_path(guest_path, **cast(Any, kwargs))
        return decision.require()

    def require_mount(self, *args: object, **kwargs: object) -> PolicyReceipt:
        decision = self.check_mount(*cast(Any, args), **cast(Any, kwargs))
        return decision.require()

    def check_network(
        self,
        host: str,
        port: int,
        method: str,
        *,
        phase: str | None = None,
        purpose: str | None = None,
        byte_count: int = 0,
        bytes: int | None = None,
        policy_digest: str | None = None,
        elapsed_seconds: float | None = None,
    ) -> PolicyDecision:
        """Authorize one exact network request and account its bytes/time."""
        target = f"{host}:{port}:{method}"
        common = self._common_denial(policy_digest)
        if common is not None:
            return self._decision(
                "network.egress", False, common, target=target, phase=phase, purpose=purpose
            )
        if self.network_policy.purpose == "none":
            return self._decision(
                "network.egress",
                False,
                "network egress is denied by purpose='none'",
                target=target,
                phase=phase,
                purpose=purpose,
            )
        duration_reason = self._network_expiry_reason()
        if duration_reason is not None:
            return self._decision(
                "network.egress",
                False,
                duration_reason,
                target=target,
                phase=phase,
                purpose=purpose,
            )
        if phase is not None and phase != self.network_policy.phase:
            return self._decision(
                "network.egress",
                False,
                "network phase mismatch",
                target=target,
                phase=phase,
                purpose=purpose,
            )
        if purpose is not None and purpose != self.network_policy.purpose:
            return self._decision(
                "network.egress",
                False,
                "network purpose mismatch",
                target=target,
                phase=phase,
                purpose=purpose,
            )
        if not isinstance(host, str):
            return self._decision(
                "network.egress",
                False,
                "network host is invalid",
                target=target,
                phase=phase,
                purpose=purpose,
            )
        try:
            normalized_host = _validate_host(host)
        except ValueError as exc:
            return self._decision(
                "network.egress", False, str(exc), target=target, phase=phase, purpose=purpose
            )
        if normalized_host not in self.network_policy.egress_hosts:
            return self._decision(
                "network.egress",
                False,
                "host is not in the exact egress allow-list",
                target=target,
                phase=phase,
                purpose=purpose,
            )
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or port not in self.network_policy.egress_ports
        ):
            return self._decision(
                "network.egress",
                False,
                "port is not in the exact egress allow-list",
                target=target,
                phase=phase,
                purpose=purpose,
            )
        if not isinstance(method, str):
            return self._decision(
                "network.egress",
                False,
                "network method is invalid",
                target=target,
                phase=phase,
                purpose=purpose,
            )
        normalized_method = method.upper()
        if normalized_method not in self.network_policy.methods:
            return self._decision(
                "network.egress",
                False,
                "method is not in the exact egress allow-list",
                target=target,
                phase=phase,
                purpose=purpose,
            )
        request_bytes = byte_count if bytes is None else bytes
        if (
            isinstance(request_bytes, bool)
            or not isinstance(request_bytes, int)
            or request_bytes < 0
        ):
            return self._decision(
                "network.egress",
                False,
                "byte count must be a non-negative integer",
                target=target,
                phase=phase,
                purpose=purpose,
            )
        if elapsed_seconds is not None:
            if (
                isinstance(elapsed_seconds, bool)
                or not isinstance(elapsed_seconds, (int, float))
                or not math.isfinite(elapsed_seconds)
                or elapsed_seconds < 0
            ):
                return self._decision(
                    "network.egress",
                    False,
                    "elapsed time must be finite and non-negative",
                    target=target,
                    phase=phase,
                    purpose=purpose,
                )
            if (
                self.network_policy.max_duration_seconds is not None
                and elapsed_seconds >= self.network_policy.max_duration_seconds
            ):
                return self._decision(
                    "network.egress",
                    False,
                    "network policy duration expired",
                    target=target,
                    phase=phase,
                    purpose=purpose,
                )
        limit = self.network_policy.max_bytes
        if limit is None or self._network_bytes + request_bytes > limit:
            return self._decision(
                "network.egress",
                False,
                "network byte limit exceeded",
                target=target,
                phase=phase,
                purpose=purpose,
            )
        self._network_bytes += request_bytes
        return self._decision(
            "network.egress",
            True,
            "exact egress is allowed within policy limits",
            target=f"{normalized_host}:{port}:{normalized_method}",
            phase=phase,
            purpose=purpose,
            details={
                "host": normalized_host,
                "port": port,
                "method": normalized_method,
                "bytes": request_bytes,
                "total_bytes": self._network_bytes,
            },
        )

    check_network_egress = check_network
    authorize_network = check_network
    enforce_network = check_network

    def require_network(self, *args: object, **kwargs: object) -> PolicyReceipt:
        decision = self.check_network(*cast(Any, args), **cast(Any, kwargs))
        return decision.require()

    require_network_egress = require_network

    def before_launch(self, *, policy_digest: str | None = None) -> PolicyDecision:
        """Authorize adapter launch after validating the complete mount plan."""
        common = self._common_denial(policy_digest, require_digest=False)
        if common is not None:
            return self._decision("launch", False, common)
        if self.run_root is None:
            return self._decision("launch", False, "run_root is required before launch")
        duration_reason = self._network_expiry_reason()
        if duration_reason is not None:
            return self._decision("launch", False, duration_reason)
        for mount in self.mounts:
            decision = self.check_mount(
                mount.host_path,
                mount.guest_path,
                mount.mode,
                policy_digest=policy_digest,
            )
            if not decision.allowed:
                return self._decision(
                    "launch", False, "mount plan is not enforceable", details=decision.to_dict()
                )
        decision = self._decision(
            "launch",
            True,
            "policy validated and mount plan is enforceable",
            details={
                "policy_digest": self.policy_digest,
                "mounts": [m.to_dict() for m in self.mounts],
            },
        )
        self._launch_receipt = decision.receipt
        return decision

    admit_launch = before_launch
    authorize_launch = before_launch
    enforce_before_launch = before_launch

    def _coerce_launch_receipt(
        self, value: PolicyReceipt | PolicyDecision | Mapping[str, object] | None
    ) -> PolicyReceipt | None:
        if value is None:
            return self._launch_receipt
        if isinstance(value, PolicyDecision):
            return value.receipt
        if isinstance(value, PolicyReceipt):
            return value
        if isinstance(value, Mapping):
            try:
                return PolicyReceipt.from_dict(value)
            except ValueError:
                return None
        return None

    def before_publication(
        self,
        *,
        launch_receipt: PolicyReceipt | PolicyDecision | Mapping[str, object] | None = None,
        policy_digest: str | None = None,
        byte_count: int = 0,
        bytes: int | None = None,
    ) -> PolicyDecision:
        """Authorize publication only when the launch policy binding survives."""
        common = self._common_denial(policy_digest, require_digest=False)
        if common is not None:
            return self._decision("publication", False, common)
        receipt = self._coerce_launch_receipt(launch_receipt)
        if receipt is None or receipt.operation != "launch" or not receipt.allowed:
            return self._decision("publication", False, "an allowed launch receipt is required")
        if not receipt.verify(self.policy_digest):
            return self._decision("publication", False, "launch receipt policy digest mismatch")
        request_bytes = byte_count if bytes is None else bytes
        duration_reason = self._network_expiry_reason()
        if duration_reason is not None:
            return self._decision("publication", False, duration_reason)
        if (
            isinstance(request_bytes, bool)
            or not isinstance(request_bytes, int)
            or request_bytes < 0
        ):
            return self._decision(
                "publication", False, "publication byte count must be non-negative"
            )
        limit = self.network_policy.max_bytes
        if limit is not None and self._network_bytes + request_bytes > limit:
            return self._decision("publication", False, "publication exceeds network byte limit")
        if self._published:
            return self._decision("publication", False, "publication has already been authorized")
        self._published = True
        return self._decision(
            "publication",
            True,
            "publication is bound to the admitted policy",
            details={
                "launch_receipt_id": receipt.receipt_id,
                "policy_digest": self.policy_digest,
                "bytes": request_bytes,
            },
        )

    authorize_publication = before_publication
    enforce_publication = before_publication
    before_publish = before_publication
    enforce_before_publication = before_publication

    def check_policy_digest(self, candidate: str | None) -> PolicyDecision:
        """Return a typed binding decision without authorizing another operation."""
        reason = self._common_denial(candidate, require_digest=True)
        if reason is not None:
            return self._decision("policy_digest", False, reason)
        return self._decision(
            "policy_digest", True, "policy digest matches", details={"digest": self.policy_digest}
        )

    bind_policy_digest = check_policy_digest

    def wipe(self, *, reason: str = "policy_wipe") -> PolicyReceipt:
        """Wipe adapter-owned state at most once and return its receipt."""
        return self._wipe_state.wipe(
            reason=reason,
            policy_digest=self.policy_digest,
            issued_at=_validate_clock(self._clock),
        )

    wipe_once = wipe
    close = wipe


# Stateless convenience wrappers retain the predicate/require shape of the
# existing permissions module while using the stronger host-boundary model.
def enforce_storage_path(
    storage_policy: StoragePolicy | Mapping[str, object],
    guest_path: str | Path,
    *,
    operation: str = "read",
    host_path: str | Path | None = None,
    run_root: str | Path | None = None,
    network_policy: NetworkPolicy | Mapping[str, object] | None = None,
    policy_digest: str | None = None,
) -> PolicyDecision:
    network = network_policy if network_policy is not None else NetworkPolicy()
    enforcer = PolicyEnforcer(storage_policy, network, run_root=run_root)
    return enforcer.check_storage(
        guest_path,
        operation=operation,
        host_path=host_path,
        policy_digest=policy_digest,
    )


def enforce_network_egress(
    network_policy: NetworkPolicy | Mapping[str, object],
    host: str,
    port: int,
    method: str,
    *,
    phase: str | None = None,
    purpose: str | None = None,
    byte_count: int = 0,
    policy_digest: str | None = None,
    clock: Callable[[], float] | None = None,
) -> PolicyDecision:
    enforcer = PolicyEnforcer(StoragePolicy(), network_policy, clock=clock)
    return enforcer.check_network(
        host,
        port,
        method,
        phase=phase,
        purpose=purpose,
        byte_count=byte_count,
        policy_digest=policy_digest,
    )


# Naming aliases keep the public adapter seam discoverable without creating
# parallel implementations.
enforce_storage = enforce_storage_path
enforce_network = enforce_network_egress
validate_runtime_policy = validate_policy
EnforcementReceipt = PolicyReceipt
StorageDecision = PolicyDecision
NetworkDecision = PolicyDecision
PolicyViolation = PolicyDenied


__all__ = [
    "DecisionKind",
    "MountBinding",
    "NetworkRequest",
    "PolicyBindingError",
    "PolicyDecision",
    "PolicyDenied",
    "PolicyEnforcer",
    "PolicyReceipt",
    "PolicyValidation",
    "PolicyValidationError",
    "ValidationResult",
    "WipeState",
    "enforce_network_egress",
    "enforce_storage_path",
    "validate_policies",
    "validate_policy",
]
