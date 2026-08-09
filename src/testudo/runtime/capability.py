"""Host-issued capability tokens and fail-closed worker supervision."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


class CapabilityError(ValueError):
    """A token or requested capability is invalid."""


class WorkerTerminated(RuntimeError):
    """The supervisor revoked and terminated the worker."""


def _time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError as exc:
        raise CapabilityError(f"invalid timestamp: {value}") from exc


def _canonical(payload: Mapping[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _signature(key: bytes, payload: Mapping[str, object]) -> str:
    return hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class CapabilityToken:
    """Immutable, host-signed scope for one VM run.

    The signing key remains host-side. The serialized token may be mounted
    read-only in a VM and presented to the host broker, but cannot be renewed
    or re-signed by the worker.
    """

    token_id: str
    run_id: str
    lease_id: str
    host_id: str
    vm_id: str
    repository: str
    branch: str
    base_sha: str
    capabilities: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    allowed_commands: tuple[str, ...]
    issued_at: str
    expires_at: str
    nonce: str
    signature: str

    SCHEMA = "contained_capability.v1"

    def payload(self) -> dict[str, object]:
        return {
            "schema": self.SCHEMA,
            "token_id": self.token_id,
            "run_id": self.run_id,
            "lease_id": self.lease_id,
            "host_id": self.host_id,
            "vm_id": self.vm_id,
            "repository": self.repository,
            "branch": self.branch,
            "base_sha": self.base_sha,
            "capabilities": list(self.capabilities),
            "allowed_paths": list(self.allowed_paths),
            "allowed_commands": list(self.allowed_commands),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
        }

    def to_dict(self) -> dict[str, object]:
        return {**self.payload(), "signature": self.signature}

    @classmethod
    def issue(
        cls,
        *,
        signing_key: bytes,
        run_id: str,
        lease_id: str,
        host_id: str,
        vm_id: str,
        repository: str,
        branch: str,
        base_sha: str,
        capabilities: tuple[str, ...],
        allowed_paths: tuple[str, ...] = (),
        allowed_commands: tuple[str, ...] = (),
        lifetime: timedelta,
        now: datetime | None = None,
    ) -> CapabilityToken:
        if not signing_key or lifetime <= timedelta(0):
            raise CapabilityError("signing key and positive lifetime are required")
        if not all((run_id, lease_id, host_id, vm_id, repository, branch, base_sha)):
            raise CapabilityError("run, lease, host, VM, repository and scope are required")
        if not branch.startswith("agent/"):
            raise CapabilityError("capability token must target an agent branch")
        if len(base_sha) not in (40, 64) or any(c not in "0123456789abcdef" for c in base_sha):
            raise CapabilityError("base_sha must be a lowercase Git/object digest")
        issued = (now or datetime.now(UTC)).astimezone(UTC)
        payload = {
            "schema": cls.SCHEMA,
            "token_id": secrets.token_hex(16),
            "run_id": run_id,
            "lease_id": lease_id,
            "host_id": host_id,
            "vm_id": vm_id,
            "repository": repository,
            "branch": branch,
            "base_sha": base_sha,
            "capabilities": list(capabilities),
            "allowed_paths": list(allowed_paths),
            "allowed_commands": list(allowed_commands),
            "issued_at": _time(issued),
            "expires_at": _time(issued + lifetime),
            "nonce": secrets.token_hex(16),
        }
        return cls._from_payload(payload, _signature(signing_key, payload))

    @classmethod
    def verify(
        cls,
        value: Mapping[str, Any],
        *,
        signing_key: bytes,
        now: datetime | None = None,
    ) -> CapabilityToken:
        if not signing_key or not isinstance(value, Mapping):
            raise CapabilityError("token and signing key are required")
        signature = value.get("signature")
        payload = {key: value[key] for key in value if key != "signature"}
        if payload.get("schema") != cls.SCHEMA or not isinstance(signature, str):
            raise CapabilityError("unsupported or unsigned token")
        if not hmac.compare_digest(signature, _signature(signing_key, payload)):
            raise CapabilityError("capability token signature mismatch")
        token = cls._from_payload(payload, signature)
        current = (now or datetime.now(UTC)).astimezone(UTC)
        if _parse_time(token.issued_at) > current:
            raise CapabilityError("capability token is not yet valid")
        if current >= _parse_time(token.expires_at):
            raise CapabilityError("capability token expired")
        return token

    @classmethod
    def _from_payload(cls, payload: Mapping[str, Any], signature: str) -> CapabilityToken:
        names = ("token_id", "run_id", "lease_id", "host_id", "vm_id", "repository", "branch", "base_sha", "issued_at", "expires_at", "nonce")
        if any(not isinstance(payload.get(name), str) or not payload[name] for name in names):
            raise CapabilityError("token identity or time field is missing")
        lists: list[tuple[str, ...]] = []
        for name in ("capabilities", "allowed_paths", "allowed_commands"):
            value = payload.get(name)
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise CapabilityError(f"{name} must be a string list")
            lists.append(tuple(value))
        token = cls(
            token_id=payload["token_id"], run_id=payload["run_id"], lease_id=payload["lease_id"],
            host_id=payload["host_id"], vm_id=payload["vm_id"], repository=payload["repository"],
            branch=payload["branch"], base_sha=payload["base_sha"], capabilities=lists[0],
            allowed_paths=lists[1], allowed_commands=lists[2], issued_at=payload["issued_at"],
            expires_at=payload["expires_at"], nonce=payload["nonce"], signature=signature,
        )
        _parse_time(token.issued_at)
        _parse_time(token.expires_at)
        return token


@dataclass(frozen=True, slots=True)
class SupervisorEvent:
    event: str
    reason: str
    token_id: str
    at: str


class WorkerSupervisor:
    """Host-side expiry and kill/wipe boundary for one worker VM."""

    def __init__(
        self, token: CapabilityToken, *, signing_key: bytes,
        kill_vm: Callable[[], None], wipe_vm: Callable[[], None],
        revoke_token: Callable[[str], None], event_sink: Callable[[SupervisorEvent], None] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.token = token
        self._key = signing_key
        self._kill = kill_vm
        self._wipe = wipe_vm
        self._revoke = revoke_token
        self._sink = event_sink or (lambda _event: None)
        self._now = now or (lambda: datetime.now(UTC))
        self._tripped = False

    @property
    def tripped(self) -> bool:
        return self._tripped

    def check_expiry(self) -> None:
        try:
            CapabilityToken.verify(self.token.to_dict(), signing_key=self._key, now=self._now())
        except CapabilityError as exc:
            self.trip(f"token_invalid_or_expired:{exc}")
            raise WorkerTerminated(str(exc)) from exc

    def checkpoint_due(self, margin: timedelta = timedelta(minutes=5)) -> bool:
        self.check_expiry()
        return _parse_time(self.token.expires_at) - self._now().astimezone(UTC) <= margin

    def request(self, capability: str, *, target: str = "microvm", destructive: bool = False) -> None:
        self.check_expiry()
        if target != "microvm":
            self.trip("host_boundary_operation_attempt")
            raise WorkerTerminated("host-boundary operation attempted")
        if capability not in self.token.capabilities:
            if destructive:
                self.trip("unauthorized_destructive_operation")
                raise WorkerTerminated("unauthorized destructive operation")
            raise CapabilityError(f"capability not granted: {capability}")

    def trip(self, reason: str) -> SupervisorEvent:
        event = SupervisorEvent("worker_trip", reason, self.token.token_id, _time(self._now()))
        if self._tripped:
            return event
        self._tripped = True
        self._sink(event)
        self._revoke(self.token.token_id)
        self._kill()
        self._wipe()
        return event


def write_token(path: Path | str, token: CapabilityToken) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{secrets.token_hex(8)}")
    try:
        temporary.write_text(json.dumps(token.to_dict(), sort_keys=True, separators=(",", ":")) + "\n")
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)
