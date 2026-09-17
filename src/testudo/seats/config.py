# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""P1-P4 closed-schema persistence for seats.v1.json and state.v1.json.

The bridge is the sole writer. Every mutation supplies a bridge-issued
expected revision; under an exclusive no-follow ``flock`` on a regular,
current-user-owned 0600 sibling lock file, the bridge rereads and validates
the current file, rejects a revision mismatch as ``conflict``, applies one
mutation, increments revision, fsyncs a current-user-owned 0600 temporary
file in the same directory, renames it atomically, and fsyncs the 0700
parent directory. Invalid JSON/schema is never partially loaded: it is
atomically renamed to a quarantine name and replaced with a valid empty
revision-0 file.
"""

from __future__ import annotations

import copy
import errno
import fcntl
import json
import os
import re
import secrets
import stat
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from testudo.seats.validation import (
    ValidationError,
    canonical_hostname,
    validate_absolute_path,
    validate_boot_id,
    validate_fingerprint,
    validate_hex64,
    validate_label,
    validate_launch_argv,
    validate_model_id,
    validate_port,
    validate_rfc3339_utc,
    validate_seat_template,
    validate_ssh_alias,
    validate_ssh_kind,
    validate_ssh_user,
    validate_subcommand,
    validate_timeout,
    validate_transport_kind,
    validate_unit,
    validate_uuid4,
)

SCHEMA_SEATS = "testudo.seats.v1"
SCHEMA_STATE = "testudo.state.v1"
POLICY_VERSION = 5
MAX_HOSTS = 16
MAX_SEATS_PER_HOST = 32
MAX_SEATS_TOTAL = 512
MAX_CONFIG_BYTES = 1024 * 1024
MAX_READY_TIMEOUT = 1800
MIN_READY_TIMEOUT = 30

_CONSENT_KEYS = frozenset(
    {
        "digest",
        "accepted_at",
        "policy_version",
        "ssh_effective_sha256",
        "host_key_fingerprint",
    }
)
_HOST_KEYS = frozenset({"id", "label", "ssh", "transport", "consent", "seats"})
_SEAT_COMMON_KEYS = frozenset(
    {"id", "label", "template", "model_id", "port", "endpoint_host", "ready_timeout"}
)
_TEMPLATE_KEYS = {
    "systemd-user": frozenset({"unit"}),
    "control-script": frozenset(
        {"script", "start_subcommand", "stop_subcommand", "status_subcommand"}
    ),
    "bare-command": frozenset({"launch_argv", "cwd"}),
}
_TRANSPORT_KEYS = frozenset({"kind"})
_SSH_ALIAS_KEYS = frozenset({"kind", "alias"})
_SSH_EXPLICIT_REQUIRED_KEYS = frozenset({"kind", "user", "host", "port"})
_SSH_EXPLICIT_KEYS = _SSH_EXPLICIT_REQUIRED_KEYS | {"key_path"}
_PID_RECORD_KEYS = frozenset(
    {
        "host_id",
        "seat_id",
        "ssh_hostname",
        "ssh_port",
        "endpoint_host",
        "endpoint_port",
        "pid",
        "pgid",
        "proc_start_ticks",
        "boot_id",
        "argv_sha256",
    }
)


class ConflictError(Exception):
    """A mutation lost the revision race; the caller must re-read and retry."""


class StoreCorruptError(Exception):
    """The persisted file was quarantined; ``quarantine_path`` names the copy."""

    def __init__(self, quarantine_path: str) -> None:
        self.quarantine_path = quarantine_path
        super().__init__(f"corrupt store quarantined at {quarantine_path}")


# --- schema validation (P1: closed recursively) ------------------------------


def _closed_object(field: str, value: Any, allowed: frozenset[str] | set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(field, "type", "expected an object")
    unknown = set(value) - set(allowed)
    if unknown:
        raise ValidationError(field, "unknown-field", f"{sorted(unknown)}")
    missing = set(allowed) - set(value)
    if missing:
        raise ValidationError(field, "missing-field", f"{sorted(missing)}")
    return value


def _closed_object_with_kind(
    field: str,
    value: Any,
    variants: dict[str, frozenset[str]],
    optional: dict[str, frozenset[str]],
    kind_field: str,
) -> dict[str, Any]:
    """A closed object whose exact key set depends on a discriminator field.
    ``variants[kind]`` is the required key set; ``optional[kind]`` lists keys
    allowed but not required. Keys belonging to another variant are rejected
    as unknown."""
    if not isinstance(value, dict):
        raise ValidationError(field, "type", "expected an object")
    all_keys: set[str] = set()
    for kind_keys, kind_optional in zip(variants.values(), optional.values(), strict=True):
        all_keys |= set(kind_keys) | set(kind_optional)
    unknown = set(value) - all_keys
    if unknown:
        raise ValidationError(field, "unknown-field", f"{sorted(unknown)}")
    kind = value.get(kind_field)
    if not isinstance(kind, str) or kind not in variants:
        raise ValidationError(f"{field}.{kind_field}", "discriminator")
    missing = set(variants[kind]) - set(value)
    if missing:
        raise ValidationError(field, "missing-field", f"{sorted(missing)}")
    return value


def _require_str(field: str, value: Any) -> str:
    if not isinstance(value, str):
        raise ValidationError(field, "type", "expected a string")
    return value


def validate_ssh_descriptor(field: str, value: Any) -> dict[str, Any]:
    obj = _closed_object_with_kind(
        field,
        value,
        {"alias": _SSH_ALIAS_KEYS, "explicit": _SSH_EXPLICIT_REQUIRED_KEYS},
        {"alias": frozenset(), "explicit": frozenset({"key_path"})},
        "kind",
    )
    kind = _require_str(f"{field}.kind", obj["kind"])
    validate_ssh_kind(f"{field}.kind", kind)
    if kind == "alias":
        validate_ssh_alias(f"{field}.alias", _require_str(f"{field}.alias", obj["alias"]))
        return obj
    validate_ssh_user(f"{field}.user", _require_str(f"{field}.user", obj["user"]))
    canonical_hostname(f"{field}.host", _require_str(f"{field}.host", obj["host"]))
    validate_port(f"{field}.port", obj["port"])
    if "key_path" in obj:
        validate_absolute_path(
            f"{field}.key_path", _require_str(f"{field}.key_path", obj["key_path"])
        )
    return obj


def validate_transport(field: str, value: Any) -> dict[str, Any]:
    obj = _closed_object(field, value, _TRANSPORT_KEYS)
    kind = _require_str(f"{field}.kind", obj["kind"])
    validate_transport_kind(f"{field}.kind", kind)
    return obj


def validate_consent(field: str, value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    obj = _closed_object(field, value, _CONSENT_KEYS)
    validate_hex64(f"{field}.digest", _require_str(f"{field}.digest", obj["digest"]))
    validate_rfc3339_utc(
        f"{field}.accepted_at", _require_str(f"{field}.accepted_at", obj["accepted_at"])
    )
    if obj["policy_version"] != POLICY_VERSION or isinstance(obj["policy_version"], bool):
        raise ValidationError(f"{field}.policy_version", "policy-version")
    validate_hex64(
        f"{field}.ssh_effective_sha256",
        _require_str(f"{field}.ssh_effective_sha256", obj["ssh_effective_sha256"]),
    )
    validate_fingerprint(
        f"{field}.host_key_fingerprint",
        _require_str(f"{field}.host_key_fingerprint", obj["host_key_fingerprint"]),
    )
    return obj


def validate_seat(field: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(field, "type", "expected an object")
    template = value.get("template")
    if not isinstance(template, str):
        raise ValidationError(f"{field}.template", "type")
    validate_seat_template(f"{field}.template", template)
    allowed = _SEAT_COMMON_KEYS | _TEMPLATE_KEYS[template]
    obj = _closed_object(field, value, allowed)
    validate_uuid4(f"{field}.id", _require_str(f"{field}.id", obj["id"]))
    validate_label(f"{field}.label", _require_str(f"{field}.label", obj["label"]))
    validate_model_id(f"{field}.model_id", _require_str(f"{field}.model_id", obj["model_id"]))
    validate_port(f"{field}.port", obj["port"])
    canonical_hostname(
        f"{field}.endpoint_host", _require_str(f"{field}.endpoint_host", obj["endpoint_host"])
    )
    validate_timeout(
        f"{field}.ready_timeout", obj["ready_timeout"], MIN_READY_TIMEOUT, MAX_READY_TIMEOUT
    )
    if template == "systemd-user":
        validate_unit(f"{field}.unit", _require_str(f"{field}.unit", obj["unit"]))
    elif template == "control-script":
        validate_absolute_path(f"{field}.script", _require_str(f"{field}.script", obj["script"]))
        for key in ("start_subcommand", "stop_subcommand", "status_subcommand"):
            validate_subcommand(f"{field}.{key}", _require_str(f"{field}.{key}", obj[key]))
    else:
        validate_launch_argv(f"{field}.launch_argv", obj["launch_argv"])
        validate_absolute_path(f"{field}.cwd", _require_str(f"{field}.cwd", obj["cwd"]))
    return obj


def validate_host(field: str, value: Any) -> dict[str, Any]:
    obj = _closed_object(field, value, _HOST_KEYS)
    validate_uuid4(f"{field}.id", _require_str(f"{field}.id", obj["id"]))
    validate_label(f"{field}.label", _require_str(f"{field}.label", obj["label"]))
    validate_ssh_descriptor(f"{field}.ssh", obj["ssh"])
    validate_transport(f"{field}.transport", obj["transport"])
    validate_consent(f"{field}.consent", obj["consent"])
    if not isinstance(obj["seats"], list):
        raise ValidationError(f"{field}.seats", "type", "expected an array")
    if len(obj["seats"]) > MAX_SEATS_PER_HOST:
        raise ValidationError(f"{field}.seats", "cardinality", ">32 seats per host")
    for index, seat in enumerate(obj["seats"]):
        validate_seat(f"{field}.seats[{index}]", seat)
    return obj


def validate_seats_config(value: Any) -> dict[str, Any]:
    """Validate a complete parsed seats.v1.json document (P1)."""
    obj = _closed_object("config", value, {"schema", "revision", "hosts"})
    if obj["schema"] != SCHEMA_SEATS:
        raise ValidationError("config.schema", "schema")
    revision = obj["revision"]
    if (
        not isinstance(revision, int)
        or isinstance(revision, bool)
        or not 0 <= revision <= 9_007_199_254_740_991
    ):
        raise ValidationError("config.revision", "revision")
    if not isinstance(obj["hosts"], list):
        raise ValidationError("config.hosts", "type", "expected an array")
    if len(obj["hosts"]) > MAX_HOSTS:
        raise ValidationError("config.hosts", "cardinality", ">16 hosts")
    total_seats = 0
    seen_ids: set[str] = set()
    endpoints: set[tuple[str, int, str]] = set()
    shared: set[tuple[str, int]] = set()
    for index, host in enumerate(obj["hosts"]):
        validate_host(f"config.hosts[{index}]", host)
        host_id = host["id"]
        if host_id in seen_ids:
            raise ValidationError(f"config.hosts[{index}].id", "duplicate-id")
        seen_ids.add(host_id)
        for seat in host["seats"]:
            total_seats += 1
            seat_id = seat["id"]
            if seat_id in seen_ids:
                raise ValidationError(f"config.hosts[{index}].seats[].id", "duplicate-id")
            seen_ids.add(seat_id)
            key = (seat["endpoint_host"], seat["port"], seat["model_id"])
            if key in endpoints:
                raise ValidationError(
                    f"config.hosts[{index}].seats[].endpoint", "duplicate-endpoint-model"
                )
            endpoints.add(key)
            shared.add((seat["endpoint_host"], seat["port"]))
    if total_seats > MAX_SEATS_TOTAL:
        raise ValidationError("config.hosts", "cardinality", ">512 seats total")
    return obj


def shared_endpoint_pairs(config: dict[str, Any]) -> set[tuple[str, int]]:
    """(endpoint_host, port) pairs used by more than one seat (P1 warning)."""
    counts: dict[tuple[str, int], int] = {}
    for host in config["hosts"]:
        for seat in host["seats"]:
            pair = (seat["endpoint_host"], seat["port"])
            counts[pair] = counts.get(pair, 0) + 1
    return {pair for pair, count in counts.items() if count > 1}


def empty_seats_config() -> dict[str, Any]:
    return {"schema": SCHEMA_SEATS, "revision": 0, "hosts": []}


# --- P2/P3: locked, atomic, self-healing file store --------------------------

_QUARANTINE_TS_RE = re.compile(r"^\d{15,}$")


def _check_no_symlink(path: Path) -> None:
    if path.is_symlink():
        raise OSError(errno.EPERM, f"symlink not permitted: {path}")


def _check_file_owner_mode(path: Path) -> None:
    """Regular file, current-user-owned, mode 0600 (after umask application)."""
    st = path.stat()
    if not stat.S_ISREG(st.st_mode):
        raise OSError(errno.EPERM, f"not a regular file: {path}")
    if st.st_uid != os.getuid():
        raise OSError(errno.EPERM, f"not owned by current user: {path}")
    if stat.S_IMODE(st.st_mode) != 0o600:
        raise OSError(errno.EPERM, f"unsafe mode {oct(stat.S_IMODE(st.st_mode))}: {path}")


def _check_dir(path: Path) -> None:
    st = path.stat()
    if not stat.S_ISDIR(st.st_mode):
        raise OSError(errno.EPERM, f"not a directory: {path}")
    if st.st_uid != os.getuid():
        raise OSError(errno.EPERM, f"not owned by current user: {path}")


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write_locked(path: Path, text: str) -> None:
    """Write ``text`` atomically: 0600 temp in the same dir, fsync, rename,
    fsync parent. Caller holds the store lock and has verified the dir."""
    directory = path.parent
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=directory)
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        _fsync_dir(directory)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


class _StoreLock:
    """Exclusive no-follow flock on a 0600 sibling lock file."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def __enter__(self) -> None:
        lock_path = self.path.parent / f".{self.path.name}.lock"
        _check_no_symlink(lock_path)
        if not lock_path.exists():
            # create atomically: O_CREAT|O_EXCL, then verify
            try:
                fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
            except FileExistsError:
                pass
        _check_file_owner_mode(lock_path)
        self._fd = os.open(lock_path, os.O_RDWR)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX)
        except OSError:
            os.close(self._fd)
            raise
        return None

    def __exit__(self, *exc: object) -> None:
        os.close(self._fd)


class SeatStore:
    """Bridge-owned seats.v1.json (P1-P3)."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)

    def load(self) -> dict[str, Any]:
        """Read and fully validate the config; quarantine corrupt files (P3)."""
        with _StoreLock(self.path):
            _check_no_symlink(self.path)
            return self._load_locked()

    def _load_locked(self) -> dict[str, Any]:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            config = empty_seats_config()
            self._write_locked(json.dumps(config, separators=(",", ":")))
            return config
        if len(raw) > MAX_CONFIG_BYTES:
            self._quarantine_locked()
            raise StoreCorruptError(str(self.path))
        try:
            parsed: Any = json.loads(raw.decode("utf-8"))
            validate_seats_config(parsed)
        except (UnicodeDecodeError, json.JSONDecodeError, ValidationError):
            self._quarantine_locked()
            raise StoreCorruptError(str(self.path)) from None
        assert isinstance(parsed, dict)
        return parsed

    def _quarantine_locked(self) -> None:
        timestamp = f"{int(time.time() * 1000):016d}"
        suffix = secrets.token_hex(4)
        target = self.path.parent / f"{self.path.name}.quarantine-{timestamp}-{suffix}"
        os.replace(self.path, target)
        os.chmod(target, 0o600)
        _fsync_dir(self.path.parent)
        self._write_locked(json.dumps(empty_seats_config(), separators=(",", ":")))

    def _write_locked(self, text: str) -> None:
        _atomic_write_locked(self.path, text)

    def mutate(
        self,
        expected_revision: int,
        mutation: Any,
    ) -> dict[str, Any]:
        """Apply one mutation under the lock (P2).

        ``mutation`` is a callable receiving the validated current config and
        returning None (in-place edit of the passed object) or a replacement
        config object. Revision mismatch raises :class:`ConflictError`.
        """
        with _StoreLock(self.path):
            try:
                current = self._load_locked()
            except StoreCorruptError:
                # after quarantine the store is a fresh revision-0 file
                current = self._load_locked()
            if current["revision"] != expected_revision:
                raise ConflictError(
                    f"expected revision {expected_revision}, found {current['revision']}"
                )
            working = copy.deepcopy(current)
            result = mutation(working)
            updated = working if result is None else result
            validate_seats_config(updated)
            updated["revision"] = current["revision"] + 1
            self._write_locked(json.dumps(updated, separators=(",", ":")))
            return updated


# --- P4: runtime state -------------------------------------------------------

MAX_STATE_BYTES = 1024 * 1024
MAX_PID_RECORDS = 512
_PID_INT_MAX = 2_147_483_647


def validate_pid_record(field: str, value: Any) -> dict[str, Any]:
    obj = _closed_object(field, value, _PID_RECORD_KEYS)
    validate_uuid4(f"{field}.host_id", _require_str(f"{field}.host_id", obj["host_id"]))
    validate_uuid4(f"{field}.seat_id", _require_str(f"{field}.seat_id", obj["seat_id"]))
    canonical_hostname(
        f"{field}.ssh_hostname", _require_str(f"{field}.ssh_hostname", obj["ssh_hostname"])
    )
    validate_port(f"{field}.ssh_port", obj["ssh_port"])
    canonical_hostname(
        f"{field}.endpoint_host", _require_str(f"{field}.endpoint_host", obj["endpoint_host"])
    )
    validate_port(f"{field}.endpoint_port", obj["endpoint_port"])
    for key in ("pid", "pgid", "proc_start_ticks"):
        number = obj[key]
        if (
            not isinstance(number, int)
            or isinstance(number, bool)
            or not 1 <= number <= _PID_INT_MAX
        ):
            raise ValidationError(f"{field}.{key}", "integer-range")
    validate_boot_id(f"{field}.boot_id", _require_str(f"{field}.boot_id", obj["boot_id"]))
    validate_hex64(f"{field}.argv_sha256", _require_str(f"{field}.argv_sha256", obj["argv_sha256"]))
    return obj


def validate_state(value: Any) -> dict[str, Any]:
    obj = _closed_object("state", value, {"schema", "revision", "pid_records"})
    if obj["schema"] != SCHEMA_STATE:
        raise ValidationError("state.schema", "schema")
    revision = obj["revision"]
    if (
        not isinstance(revision, int)
        or isinstance(revision, bool)
        or not 0 <= revision <= 9_007_199_254_740_991
    ):
        raise ValidationError("state.revision", "revision")
    if not isinstance(obj["pid_records"], list):
        raise ValidationError("state.pid_records", "type")
    if len(obj["pid_records"]) > MAX_PID_RECORDS:
        raise ValidationError("state.pid_records", "cardinality")
    seen: set[tuple[str, str]] = set()
    for index, record in enumerate(obj["pid_records"]):
        validate_pid_record(f"state.pid_records[{index}]", record)
        key = (record["host_id"], record["seat_id"])
        if key in seen:
            raise ValidationError(f"state.pid_records[{index}]", "duplicate-seat-record")
        seen.add(key)
    return obj


def empty_state() -> dict[str, Any]:
    return {"schema": SCHEMA_STATE, "revision": 0, "pid_records": []}


@dataclass
class _QuarantineResult:
    quarantined: list[dict[str, Any]]
    path: str


class StateStore:
    """Bridge-owned state.v1.json (P4): operation observations and Template C
    PID records, same locking/atomic/quarantine algorithm as P2/P3."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)

    def load(self) -> dict[str, Any]:
        with _StoreLock(self.path):
            _check_no_symlink(self.path)
            return self._load_locked()

    def _load_locked(self) -> dict[str, Any]:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            state = empty_state()
            self._write_locked(json.dumps(state, separators=(",", ":")))
            return state
        if len(raw) > MAX_STATE_BYTES:
            self._quarantine_locked()
            raise StoreCorruptError(str(self.path))
        try:
            parsed: Any = json.loads(raw.decode("utf-8"))
            validate_state(parsed)
        except (UnicodeDecodeError, json.JSONDecodeError, ValidationError):
            self._quarantine_locked()
            raise StoreCorruptError(str(self.path)) from None
        assert isinstance(parsed, dict)
        return parsed

    def _quarantine_locked(self) -> None:
        timestamp = f"{int(time.time() * 1000):016d}"
        suffix = secrets.token_hex(4)
        target = self.path.parent / f"{self.path.name}.quarantine-{timestamp}-{suffix}"
        os.replace(self.path, target)
        os.chmod(target, 0o600)
        _fsync_dir(self.path.parent)
        self._write_locked(json.dumps(empty_state(), separators=(",", ":")))

    def _write_locked(self, text: str) -> None:
        _atomic_write_locked(self.path, text)

    def mutate(self, expected_revision: int, mutation: Any) -> dict[str, Any]:
        with _StoreLock(self.path):
            try:
                current = self._load_locked()
            except StoreCorruptError:
                current = self._load_locked()
            if current["revision"] != expected_revision:
                raise ConflictError(
                    f"expected revision {expected_revision}, found {current['revision']}"
                )
            working = copy.deepcopy(current)
            result = mutation(working)
            updated = working if result is None else result
            validate_state(updated)
            updated["revision"] = current["revision"] + 1
            self._write_locked(json.dumps(updated, separators=(",", ":")))
            return updated
