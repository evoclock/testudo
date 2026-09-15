# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Explicit macOS ``container`` CLI adapter for one governed run.

This adapter intentionally uses Apple's native ``container`` command, not a
Docker-compatible fallback.  It builds one non-interactive, no-network command
with a read-only image/root filesystem and only the run-local mounts declared by
:class:`~testudo.runtime.policy.StoragePolicy`.  Workflow and input mappings
cross the boundary over the existing framed broker protocol on the child
process's stdin/stdout; no socket, listener, service, image pull, credential,
or publication path is created here.

The adapter is a host boundary, not a policy store.  Callers provide the
lease/run/artifact/policy identity and optional revocation/wipe callbacks.  The
identity is repeated in command labels, a read-only guest contract, and every
broker frame, so a mismatched guest cannot produce an accepted result.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import select
import subprocess
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Protocol, cast

from testudo.runtime.broker import BrokerSession
from testudo.runtime.capability import CapabilityToken, SupervisorEvent
from testudo.runtime.containment import containment_contract
from testudo.runtime.controller import HostEvent, HostEventName, HostReceipt, StopHandle
from testudo.runtime.isolation import IsolationProfile
from testudo.runtime.signing import TokenSigner
from testudo.runtime.transport import MAX_FRAME_BYTES
from testudo.runtime.worker import VMHandle, WorkerLifecycle

MAX_STDIO_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_BYTES = MAX_STDIO_BYTES
GUEST_PROTOCOL = "testudo.vsock.frame.v1"
GUEST_MODE: Literal["stdio"] = "stdio"
_NATIVE_CLI = "container"
_SUPERVISOR_ENTRY = "/opt/testudo/testudo_contained_guest.sh"
_RUN_ID_ENV = "TESTUDO_RUN_ID"
NATIVE_SUPERVISOR_ENTRY = _SUPERVISOR_ENTRY
NATIVE_RUN_ID_ENV = _RUN_ID_ENV
_READ_CHUNK_BYTES = 64 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTITY_VALUE = re.compile(r"^[^\x00\r\n\t ]+$")


class NativeContainerError(RuntimeError):
    """A native-container admission, protocol, process, or cleanup failure."""


class NativeContainerTimeout(NativeContainerError):
    """The guest or process exceeded its bounded wall-clock budget."""


class _BinaryReadable(Protocol):
    def read(self, size: int = -1) -> bytes | bytearray: ...

    def close(self) -> None: ...

    def fileno(self) -> int: ...


class _BinaryWritable(Protocol):
    def write(self, data: bytes) -> int | None: ...

    def flush(self) -> None: ...

    def close(self) -> None: ...


class NativeProcess(Protocol):
    """Small injected subprocess contract used by tests and the adapter."""

    stdin: _BinaryWritable | None
    stdout: _BinaryReadable | None
    stderr: _BinaryReadable | None
    pid: int

    def poll(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...


PopenFactory = Callable[..., NativeProcess]
Clock = Callable[[], float]
Hook = Callable[..., None]


def _default_popen(argv: Sequence[str], **kwargs: object) -> NativeProcess:
    """Use binary pipes and return a typed view of ``subprocess.Popen``."""
    return cast(NativeProcess, subprocess.Popen(list(argv), **cast(Any, kwargs)))


def _safe_host_env() -> dict[str, str]:
    """Return a minimal environment that cannot forward host credentials."""
    return {
        "PATH": "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin",
        "LC_ALL": "C",
    }


def _require_identity_value(name: str, value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise NativeContainerError(f"{name} is required and must be at most 256 characters")
    if _IDENTITY_VALUE.fullmatch(value) is None:
        raise NativeContainerError(f"{name} contains whitespace or control characters")
    return value


def _normalise_digest(name: str, value: str, *, allow_prefix: bool = True) -> str:
    candidate = value[7:] if allow_prefix and value.startswith("sha256:") else value
    if _SHA256.fullmatch(candidate) is None:
        raise NativeContainerError(f"{name} must be a lowercase SHA-256 digest")
    return candidate


def _under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def _guest_path(name: str, path: str, prefix: str) -> str:
    if not isinstance(path, str) or not path.startswith("/"):
        raise NativeContainerError(f"{name} must be an absolute guest path")
    pure = PurePosixPath(path)
    if ".." in pure.parts or "//" in path or not _under(path, prefix):
        raise NativeContainerError(f"{name} must remain under {prefix}")
    if "," in path or "=" in path:
        raise NativeContainerError(f"{name} contains mount syntax characters")
    return path


def _host_dir(name: str, path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_absolute() or not resolved.is_dir():
        raise NativeContainerError(f"{name} must be an existing host directory: {path}")
    if "," in str(resolved) or "=" in str(resolved):
        raise NativeContainerError(f"{name} contains mount syntax characters")
    return resolved


def _canonical(value: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise NativeContainerError("native result is not canonical JSON") from exc


def _sha256(value: Mapping[str, object]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class NativeContainerIdentity:
    """Identity shared by the host command, guest contract, and receipts.

    ``artifact_id`` is accepted as a compatibility spelling for
    ``artifact_digest``.  The digest is normalised to bare lowercase hex because
    the existing guest bootstrap's receipt contract uses that representation.
    ``token_id`` and ``nonce`` are required for the existing broker frame
    contract; deterministic defaults are provided only for command-construction
    tests and must be replaced by a host-issued identity for a real run.
    """

    lease_id: str
    run_id: str
    artifact_digest: str | None = None
    policy_digest: str = ""
    token_id: str = "native-token"
    nonce: str = "native-nonce"
    artifact_id: str | None = None

    def __post_init__(self) -> None:
        lease_id = _require_identity_value("lease_id", self.lease_id)
        run_id = _require_identity_value("run_id", self.run_id)
        raw_artifact = self.artifact_digest or self.artifact_id
        if raw_artifact is None:
            raise NativeContainerError("artifact_digest is required")
        artifact = _normalise_digest("artifact_digest", raw_artifact)
        policy = _normalise_digest("policy_digest", self.policy_digest, allow_prefix=False)
        token = _require_identity_value("token_id", self.token_id)
        nonce = _require_identity_value("nonce", self.nonce)
        if (
            self.artifact_digest is not None
            and self.artifact_id is not None
            and _normalise_digest("artifact_id", self.artifact_id) != artifact
        ):
            raise NativeContainerError("artifact_id and artifact_digest do not match")
        object.__setattr__(self, "lease_id", lease_id)
        object.__setattr__(self, "run_id", run_id)
        object.__setattr__(self, "artifact_digest", artifact)
        object.__setattr__(self, "artifact_id", artifact)
        object.__setattr__(self, "policy_digest", policy)
        object.__setattr__(self, "token_id", token)
        object.__setattr__(self, "nonce", nonce)

    def contract(self) -> dict[str, str]:
        """Return the identity fields required by the guest bootstrap."""
        assert self.artifact_digest is not None
        return {
            "lease_id": self.lease_id,
            "run_id": self.run_id,
            "artifact_digest": self.artifact_digest,
            "policy_digest": self.policy_digest,
            "token_id": self.token_id,
            "nonce": self.nonce,
        }

    def labels(self) -> tuple[str, ...]:
        """Return stable native-container labels for host-side inspection."""
        assert self.artifact_digest is not None
        return (
            f"testudo.lease_id={self.lease_id}",
            f"testudo.run_id={self.run_id}",
            f"testudo.artifact_digest={self.artifact_digest}",
            f"testudo.policy_digest={self.policy_digest}",
        )


@dataclass(frozen=True, slots=True)
class StdioGuestMode:
    """Explicit guest transport contract for a process's stdin/stdout pipes."""

    name: Literal["stdio"] = GUEST_MODE
    protocol: str = GUEST_PROTOCOL

    def __post_init__(self) -> None:
        if self.name != GUEST_MODE:
            raise NativeContainerError("only the explicit stdio guest mode is supported")
        if self.protocol != GUEST_PROTOCOL:
            raise NativeContainerError("unsupported guest protocol")

    def environment(self) -> tuple[str, ...]:
        """Return fixed, non-secret environment entries for the guest."""
        return (
            f"TESTUDO_GUEST_MODE={self.name}",
            f"TESTUDO_GUEST_PROTOCOL={self.protocol}",
        )


@dataclass(frozen=True, slots=True)
class NativeContainerMount:
    """One declared run-local bind mount."""

    source: Path
    target: str
    read_only: bool
    name: Literal["workspace", "input", "cache"]

    def __post_init__(self) -> None:
        source = _host_dir(self.name, self.source)
        prefixes = {"workspace": "/runs", "input": "/inputs", "cache": "/cache"}
        target = _guest_path(self.name, self.target, prefixes[self.name])
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "target", target)

    def cli_value(self) -> str:
        suffix = ",readonly" if self.read_only else ""
        return f"type=bind,source={self.source},target={self.target}{suffix}"


@dataclass(frozen=True, slots=True)
class NativeContainerSpec:
    """Immutable admission inputs for one native-container process."""

    image: str
    workspace_dir: Path
    identity: NativeContainerIdentity
    isolation: IsolationProfile = field(default_factory=IsolationProfile)
    input_dir: Path | None = None
    cache_dir: Path | None = None
    command: tuple[str, ...] = ()
    guest_mode: StdioGuestMode = field(default_factory=StdioGuestMode)

    def __post_init__(self) -> None:
        if not isinstance(self.image, str) or not self.image or self.image.startswith("-"):
            raise NativeContainerError("a native image reference is required")
        command = (self.command,) if isinstance(self.command, str) else tuple(self.command)
        if not command:
            raise NativeContainerError(
                "native containment requires the in-image guest supervisor entry command"
            )
        if command[0] != _SUPERVISOR_ENTRY:
            raise NativeContainerError(
                "native containment requires the in-image guest supervisor as the entry command"
            )
        if any(not isinstance(part, str) or not part or "\x00" in part for part in command):
            raise NativeContainerError("guest command arguments must be non-empty text")
        object.__setattr__(self, "command", command)
        if self.isolation.network != "none":
            raise NativeContainerError("native container runs require network='none'")
        if self.isolation.network_policy.purpose != "none":
            raise NativeContainerError("native container runs cannot carry network policy intent")
        if not self.isolation.read_only:
            raise NativeContainerError("native container runs require read_only=True")
        storage = self.isolation.storage_policy
        if storage.host_mounts:
            raise NativeContainerError("arbitrary host mounts are not allowed")
        workspace_target = _guest_path("workspace", storage.workspace, "/runs")
        input_target = _guest_path("input", storage.inputs, "/inputs")
        workdir = _guest_path("workdir", self.isolation.workdir, "/")
        if not _under(workdir, workspace_target):
            raise NativeContainerError("workdir must remain under the declared workspace")
        # Command is required and must be the in-image guest supervisor entry
        # (validated above); a caller-provided command must not bypass it.
        if self.isolation.run_id_env is not None and self.isolation.run_id_env != _RUN_ID_ENV:
            raise NativeContainerError("the native adapter sets TESTUDO_RUN_ID itself")
        workspace = _host_dir("workspace", self.workspace_dir)
        object.__setattr__(self, "workspace_dir", workspace)
        if self.input_dir is not None:
            object.__setattr__(self, "input_dir", _host_dir("input", self.input_dir))
        if self.cache_dir is not None:
            if storage.cache is None:
                raise NativeContainerError("cache_dir requires a declared cache path")
            object.__setattr__(self, "cache_dir", _host_dir("cache", self.cache_dir))
        if storage.cache is not None and self.cache_dir is None:
            raise NativeContainerError("declared cache requires a run-local cache_dir")
        if storage.cache_access == "none" and self.cache_dir is not None:
            raise NativeContainerError("cache_dir requires cache_access other than 'none'")
        # Validate targets now; mounts are built only from these policy fields.
        _guest_path("workspace", workspace_target, "/runs")
        _guest_path("input", input_target, "/inputs")
        if storage.cache is not None:
            _guest_path("cache", storage.cache, "/cache")

    @property
    def policy_digest(self) -> str:
        """Return the policy digest bound into this run's identity."""
        computed = self.isolation.policy_digest
        if self.identity.policy_digest != computed:
            raise NativeContainerError("policy_digest does not match the isolation policy")
        return computed

    def mounts(self) -> tuple[NativeContainerMount, ...]:
        """Build only the workspace, input, and declared cache mounts."""
        storage = self.isolation.storage_policy
        mounts: list[NativeContainerMount] = [
            NativeContainerMount(self.workspace_dir, storage.workspace, False, "workspace")
        ]
        if self.input_dir is not None:
            mounts.append(NativeContainerMount(self.input_dir, storage.inputs, True, "input"))
        if self.cache_dir is not None:
            assert storage.cache is not None
            mounts.append(
                NativeContainerMount(
                    self.cache_dir,
                    storage.cache,
                    storage.cache_access == "read_only",
                    "cache",
                )
            )
        return tuple(mounts)

    def contract(self) -> dict[str, object]:
        """Return the read-only guest bootstrap contract, without host paths."""
        policy = self.isolation.storage_policy
        contract: dict[str, object] = {
            **self.identity.contract(),
            "protocol": self.guest_mode.protocol,
            "guest_mode": self.guest_mode.name,
            "image": self.image,
            "policy_digest": self.policy_digest,
            "network": "none",
            "read_only": True,
            "workspace": policy.workspace,
            "inputs": policy.inputs,
            "containment": containment_contract(),
        }
        if policy.cache is not None:
            contract["cache"] = policy.cache
            contract["cache_access"] = policy.cache_access
        return contract


def _coerce_spec(
    spec: NativeContainerSpec | None,
    *,
    image: str | None,
    workspace_dir: Path | None,
    runs_dir: Path | None,
    input_dir: Path | None,
    inputs_dir: Path | None,
    cache_dir: Path | None,
    identity: NativeContainerIdentity | None,
    lease_id: str | None,
    run_id: str | None,
    artifact_digest: str | None,
    artifact_id: str | None,
    policy_digest: str | None,
    token_id: str | None,
    nonce: str | None,
    isolation: IsolationProfile | None,
    command: Sequence[str] | None,
    guest_mode: StdioGuestMode | None,
) -> NativeContainerSpec:
    if spec is not None:
        if any(
            value is not None
            for value in (
                image,
                workspace_dir,
                runs_dir,
                input_dir,
                inputs_dir,
                cache_dir,
                identity,
                lease_id,
                run_id,
                artifact_digest,
                artifact_id,
                policy_digest,
                token_id,
                nonce,
                isolation,
                command,
                guest_mode,
            )
        ):
            raise NativeContainerError("spec cannot be combined with individual admission fields")
        return spec
    selected_workspace = workspace_dir or runs_dir
    if image is None or selected_workspace is None:
        raise NativeContainerError("image and workspace_dir are required")
    selected_input = input_dir or inputs_dir
    if input_dir is not None and inputs_dir is not None and input_dir != inputs_dir:
        raise NativeContainerError("input_dir and inputs_dir disagree")
    selected_isolation = isolation or IsolationProfile(run_id_env=_RUN_ID_ENV)
    if identity is None:
        if lease_id is None or run_id is None or (artifact_digest is None and artifact_id is None):
            raise NativeContainerError("lease_id, run_id and artifact_digest are required")
        identity = NativeContainerIdentity(
            lease_id=lease_id,
            run_id=run_id,
            artifact_digest=artifact_digest,
            artifact_id=artifact_id,
            policy_digest=policy_digest or selected_isolation.policy_digest,
            token_id=token_id or "native-token",
            nonce=nonce or "native-nonce",
        )
    elif any(
        value is not None
        for value in (lease_id, run_id, artifact_digest, artifact_id, policy_digest)
    ):
        raise NativeContainerError("identity cannot be combined with identity fields")
    return NativeContainerSpec(
        image=image,
        workspace_dir=selected_workspace,
        identity=identity,
        isolation=selected_isolation,
        input_dir=selected_input,
        cache_dir=cache_dir,
        command=tuple(command or (_SUPERVISOR_ENTRY,)),
        guest_mode=guest_mode or StdioGuestMode(),
    )


def build_native_container_argv(
    spec: NativeContainerSpec | None = None,
    *,
    image: str | None = None,
    workspace_dir: Path | None = None,
    runs_dir: Path | None = None,
    input_dir: Path | None = None,
    inputs_dir: Path | None = None,
    cache_dir: Path | None = None,
    identity: NativeContainerIdentity | None = None,
    lease_id: str | None = None,
    run_id: str | None = None,
    artifact_digest: str | None = None,
    artifact_id: str | None = None,
    policy_digest: str | None = None,
    token_id: str | None = None,
    nonce: str | None = None,
    isolation: IsolationProfile | None = None,
    command: Sequence[str] | None = None,
    guest_mode: StdioGuestMode | None = None,
) -> list[str]:
    """Build a native ``container run`` command without starting it.

    There is deliberately no Docker spelling, fallback command, publish flag,
    credential mount, env-file, network creation, or image-pull operation in
    this builder.  The workflow is sent through the explicit stdio guest mode,
    so the only host mounts are the declared run-local storage paths.
    """
    selected = _coerce_spec(
        spec,
        image=image,
        workspace_dir=workspace_dir,
        runs_dir=runs_dir,
        input_dir=input_dir,
        inputs_dir=inputs_dir,
        cache_dir=cache_dir,
        identity=identity,
        lease_id=lease_id,
        run_id=run_id,
        artifact_digest=artifact_digest,
        artifact_id=artifact_id,
        policy_digest=policy_digest,
        token_id=token_id,
        nonce=nonce,
        isolation=isolation,
        command=command,
        guest_mode=guest_mode,
    )
    argv: list[str] = [
        _NATIVE_CLI,
        "run",
        "--rm",
        "--interactive",
        "--read-only",
        "--network",
        "none",
        "--no-dns",
        "--progress",
        "none",
    ]
    for label in selected.identity.labels():
        argv.extend(["--label", label])
    for entry in selected.guest_mode.environment():
        argv.extend(["--env", entry])
    argv.extend(["--env", f"{_RUN_ID_ENV}={selected.identity.run_id}"])
    # The guest containment watcher's writable allowlist must match the
    # declared run-local storage policy exactly: workflow-required workspace
    # and exchange writes are sanctioned, everything else stays deny-by-default.
    argv.extend(
        [
            "--env",
            f"TESTUDO_GUEST_WORKSPACE={selected.isolation.storage_policy.workspace}",
            "--env",
            f"TESTUDO_GUEST_WRITABLE_PATHS={selected.isolation.storage_policy.workspace} /tmp/session",
        ]
    )
    for mount in selected.mounts():
        argv.extend(["--mount", mount.cli_value()])
    argv.extend(["--workdir", selected.isolation.workdir, selected.image])
    argv.extend(selected.command)
    return argv


# Neutral aliases make the adapter easy to discover without introducing a
# second implementation or a Docker fallback.
build_container_argv = build_native_container_argv
build_native_argv = build_native_container_argv


class NativeContainerDuplex:
    """Typed stdin/stdout duplex implementing ``BrokerSession``'s socket seam."""

    def __init__(
        self,
        stdin: _BinaryWritable,
        stdout: _BinaryReadable,
        *,
        read_timeout: float | None = None,
    ) -> None:
        self._stdin = stdin
        self._stdout = stdout
        self._read_timeout = read_timeout
        self._send_lock = threading.Lock()
        self._closed = False

    @property
    def read_timeout(self) -> float | None:
        return self._read_timeout

    def set_read_timeout(self, timeout: float | None) -> None:
        if timeout is not None and timeout < 0:
            raise ValueError("stdio read timeout must not be negative")
        self._read_timeout = timeout

    def sendall(self, data: bytes) -> None:
        if self._closed:
            raise NativeContainerError("stdio guest duplex is closed")
        with self._send_lock:
            remaining = memoryview(data)
            while remaining:
                written = self._stdin.write(bytes(remaining))
                if written is None:
                    written = len(remaining)
                if written <= 0:
                    raise NativeContainerError("stdio guest stdin made no progress")
                remaining = remaining[written:]
            self._stdin.flush()

    def recv(self, size: int) -> bytes:
        if self._closed:
            raise NativeContainerError("stdio guest duplex is closed")
        if size <= 0:
            raise ValueError("stdio recv size must be positive")
        timeout = self._read_timeout
        try:
            fd = self._stdout.fileno()
        except (AttributeError, OSError, ValueError):
            fd = -1
        if fd >= 0:
            if timeout is not None:
                ready, _, _ = select.select([fd], [], [], timeout)
                if not ready:
                    raise NativeContainerTimeout("guest stdio read timed out")
            return os.read(fd, size)
        value = self._stdout.read(size)
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, bytes):
            return value
        raise NativeContainerError("guest stdout returned a non-byte value")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for stream in (self._stdin, self._stdout):
            with suppress(OSError, ValueError):
                stream.close()


@dataclass(frozen=True, slots=True)
class NativeContainerOutput:
    """Bounded output captured from a native process and guest frames."""

    stdout: str
    stderr: str
    stdout_truncated: bool = False
    stderr_truncated: bool = False


class _BoundedCollector:
    def __init__(self, stream: _BinaryReadable, *, max_bytes: int) -> None:
        self._stream = stream
        self._max_bytes = max_bytes
        self._parts: list[str] = []
        self._size = 0
        self._truncated = False
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def _drain(self) -> None:
        try:
            while True:
                chunk = self._stream.read(_READ_CHUNK_BYTES)
                if not chunk:
                    return
                if isinstance(chunk, bytearray):
                    raw = bytes(chunk)
                elif isinstance(chunk, bytes):
                    raw = chunk
                else:
                    raw = str(chunk).encode("utf-8")
                text = raw.decode("utf-8", errors="replace")
                encoded = text.encode("utf-8")
                with self._lock:
                    remaining = self._max_bytes - self._size
                    if remaining <= 0:
                        self._truncated = True
                        continue
                    if len(encoded) > remaining:
                        text = encoded[:remaining].decode("utf-8", errors="ignore")
                        self._truncated = True
                    self._parts.append(text)
                    self._size += len(text.encode("utf-8"))
        except (AttributeError, OSError, ValueError):
            return

    def join(self, timeout: float | None) -> None:
        self._thread.join(timeout=timeout)

    def snapshot(self) -> tuple[str, bool]:
        with self._lock:
            return "".join(self._parts), self._truncated


def _call_hook(hook: Hook | None, identity: NativeContainerIdentity, reason: str) -> None:
    """Call hooks with the most specific supported signature.

    Existing lifecycle callbacks commonly take zero arguments (wipe) or one
    token-id argument (revoke), while a native integration benefits from the
    complete identity and reason.  Signature binding keeps this compatibility
    deterministic without catching a callback's own ``TypeError`` and invoking
    it a second time.
    """
    if hook is None:
        return
    try:
        signature = inspect.signature(hook)
    except (TypeError, ValueError):
        hook(identity, reason)
        return
    positional = [
        parameter
        for parameter in signature.parameters.values()
        if parameter.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    has_varargs = any(
        parameter.kind == inspect.Parameter.VAR_POSITIONAL
        for parameter in signature.parameters.values()
    )
    if has_varargs or len(positional) >= 2:
        hook(identity, reason)
    elif len(positional) == 1:
        hook(identity)
    else:
        hook()


class NativeContainerHandle:
    """Running native process with bounded pipes and idempotent cleanup."""

    def __init__(
        self,
        process: NativeProcess,
        spec: NativeContainerSpec,
        *,
        max_output_bytes: int = MAX_STDIO_BYTES,
        revocation_hook: Hook | None = None,
        wipe_hook: Hook | None = None,
    ) -> None:
        if max_output_bytes <= 0 or max_output_bytes > MAX_STDIO_BYTES:
            raise NativeContainerError("max_output_bytes is outside the stdio limit")
        stdin, stdout, stderr = process.stdin, process.stdout, process.stderr
        if stdin is None or stdout is None or stderr is None:
            raise NativeContainerError("native process must expose stdin, stdout and stderr pipes")
        self.process = process
        self.spec = spec
        self.duplex = NativeContainerDuplex(stdin, stdout)
        self._stderr_collector = _BoundedCollector(stderr, max_bytes=max_output_bytes)
        self._max_output_bytes = max_output_bytes
        self._guest_stdout: list[str] = []
        self._guest_stderr: list[str] = []
        self._guest_stdout_size = 0
        self._guest_stderr_size = 0
        self._revocation_hook = revocation_hook
        self._wipe_hook = wipe_hook
        self._revoked = False
        self._wiped = False
        self._cleaned = False
        self._output_lock = threading.Lock()

    def record_guest_output(self, stream: Literal["stdout", "stderr"], chunk: str) -> None:
        """Record one bounded protocol output chunk."""
        if not isinstance(chunk, str):
            raise NativeContainerError(f"guest {stream} chunk must be text")
        encoded_size = len(chunk.encode("utf-8"))
        with self._output_lock:
            if stream == "stdout":
                total = self._guest_stdout_size + encoded_size
                if total > self._max_output_bytes:
                    raise NativeContainerError("guest stdout exceeds bounded capture")
                self._guest_stdout.append(chunk)
                self._guest_stdout_size = total
            else:
                total = self._guest_stderr_size + encoded_size
                if total > self._max_output_bytes:
                    raise NativeContainerError("guest stderr exceeds bounded capture")
                self._guest_stderr.append(chunk)
                self._guest_stderr_size = total

    def collect_output(self, *, timeout: float | None = 0.5) -> NativeContainerOutput:
        """Return bounded guest frames plus native stderr diagnostics."""
        if timeout is not None and timeout < 0:
            raise ValueError("output collection timeout must not be negative")
        self._stderr_collector.join(timeout)
        host_stderr, host_truncated = self._stderr_collector.snapshot()
        with self._output_lock:
            stdout = "".join(self._guest_stdout)
            stderr = "".join(self._guest_stderr)
        if host_stderr:
            stderr += host_stderr
        return NativeContainerOutput(stdout, stderr, False, host_truncated)

    def terminate(self, *, timeout: float = 5.0) -> None:
        """Stop the process, escalating to ``kill`` when it ignores SIGTERM."""
        if timeout <= 0:
            raise NativeContainerError("termination timeout must be positive")
        if self.process.poll() is not None:
            return
        try:
            self.process.terminate()
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=timeout)
        except ProcessLookupError:
            return

    def stop(self, *, timeout: float = 5.0) -> None:
        """Alias for the governed SIGTERM/SIGKILL stop path."""
        self.terminate(timeout=timeout)

    def kill(self) -> None:
        """Immediately kill the process when a stop budget is exhausted."""
        if self.process.poll() is None:
            self.process.kill()

    def wait(self, *, timeout: float | None = None) -> int:
        """Wait for the native process and return its host-observed status."""
        return self.process.wait(timeout=timeout)

    def revoke_once(self, reason: str) -> None:
        if self._revoked:
            return
        self._revoked = True
        _call_hook(self._revocation_hook, self.spec.identity, reason)

    def wipe_once(self, reason: str) -> None:
        if self._wiped:
            return
        self._wiped = True
        _call_hook(self._wipe_hook, self.spec.identity, reason)

    def cleanup(self) -> None:
        """Close only this process's pipes once; workspace wipe is a hook."""
        if self._cleaned:
            return
        self._cleaned = True
        try:
            self.duplex.close()
        finally:
            self._stderr_collector.join(0.5)


# The worker lifecycle protocol is intentionally structural and reuses this
# handle; keeping the alias visible makes integration imports straightforward.
NativeVMHandle = NativeContainerHandle


def launch_native_container(
    spec: NativeContainerSpec,
    *,
    popen: PopenFactory = _default_popen,
    max_output_bytes: int = MAX_STDIO_BYTES,
    revocation_hook: Hook | None = None,
    wipe_hook: Hook | None = None,
    image_exists: Callable[[str], bool] | None = None,
) -> NativeContainerHandle:
    """Launch one already-admitted local image through Apple's CLI.

    The adapter never invokes an image pull.  Integrations that require an
    explicit local-image admission can provide ``image_exists``; a false result
    fails before ``container run`` is called.
    """
    # Force policy/identity validation before any process side effect.
    _ = spec.policy_digest
    if image_exists is not None and not image_exists(spec.image):
        raise NativeContainerError(f"native image is not locally admitted: {spec.image}")
    argv = build_native_container_argv(spec)
    process: NativeProcess | None = None
    try:
        process = popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            shell=False,
            start_new_session=True,
            env=_safe_host_env(),
        )
        return NativeContainerHandle(
            process,
            spec,
            max_output_bytes=max_output_bytes,
            revocation_hook=revocation_hook,
            wipe_hook=wipe_hook,
        )
    except BaseException as exc:
        if process is not None:
            with suppress(BaseException):
                process.terminate()
            with suppress(BaseException):
                process.wait(timeout=1.0)
        cleanup_failures: list[BaseException] = []
        for hook in (revocation_hook, wipe_hook):
            if hook is None:
                continue
            try:
                _call_hook(hook, spec.identity, "launch_failure")
            except BaseException as cleanup_error:
                cleanup_failures.append(cleanup_error)
        for failure in cleanup_failures:
            exc.add_note(f"native launch cleanup failed: {type(failure).__name__}: {failure}")
        if isinstance(exc, NativeContainerError):
            raise
        raise NativeContainerError(f"unable to launch native container: {exc}") from exc


class NativeContainerWorker:
    """Host-controller binding of a native handle, broker, and lifecycle."""

    def __init__(
        self,
        handle: NativeContainerHandle,
        broker: BrokerSession,
        lifecycle: WorkerLifecycle,
    ) -> None:
        self.handle = handle
        self.broker = broker
        self.lifecycle = lifecycle

    def collect_output(self, *, timeout: float | None = 5.0) -> NativeContainerOutput:
        return self.handle.collect_output(timeout=timeout)

    def close(self) -> None:
        with suppress(BaseException):
            self.broker.close()
        self.handle.cleanup()


def _identity_matches_token(spec: NativeContainerSpec, token: CapabilityToken) -> None:
    identity = spec.identity
    if identity.lease_id != token.lease_id:
        raise NativeContainerError("native lease identity does not match capability token")
    if identity.run_id != token.run_id:
        raise NativeContainerError("native run identity does not match capability token")
    if identity.token_id != token.token_id:
        raise NativeContainerError("native token identity does not match capability token")
    if identity.nonce != token.nonce:
        raise NativeContainerError("native nonce does not match capability token")


def launch_native_worker(
    spec: NativeContainerSpec,
    token: CapabilityToken,
    *,
    revoke_token: Callable[[str], None],
    wipe_vm: Callable[[], None],
    signing_key: bytes | None = None,
    signer: TokenSigner | None = None,
    event_sink: Callable[[SupervisorEvent], None] | None = None,
    now: Callable[[], Any] | None = None,
    popen: PopenFactory = _default_popen,
    image_exists: Callable[[str], bool] | None = None,
) -> NativeContainerWorker:
    """Verify a host token, launch the native process, and bind lifecycle hooks."""
    verified = CapabilityToken.verify(
        token.to_dict(),
        signing_key=signing_key,
        signer=signer,
        now=now() if now is not None else None,
    )
    _identity_matches_token(spec, verified)
    handle: NativeContainerHandle | None = None
    try:
        handle = launch_native_container(spec, popen=popen, image_exists=image_exists)
        broker = BrokerSession(
            handle.duplex,
            run_id=verified.run_id,
            token_id=verified.token_id,
            nonce=verified.nonce,
            max_bytes=MAX_FRAME_BYTES,
        )
        lifecycle = WorkerLifecycle(
            cast(VMHandle, handle),
            verified,
            signing_key=signing_key,
            signer=signer,
            revoke_token=revoke_token,
            wipe_vm=wipe_vm,
            event_sink=event_sink,
            now=now,
        )
        return NativeContainerWorker(handle, broker, lifecycle)
    except BaseException as exc:
        if handle is not None:
            with suppress(BaseException):
                handle.terminate(timeout=1.0)
            with suppress(BaseException):
                handle.cleanup()
        actions: tuple[tuple[str, Callable[[], None]], ...] = (
            ("revoke", lambda: revoke_token(verified.token_id)),
            ("wipe", wipe_vm),
        )
        for name, action in actions:
            try:
                action()
            except BaseException as cleanup_error:
                failure = cleanup_error
                exc.add_note(f"native worker {name} failed: {type(failure).__name__}: {failure}")
        raise


def open_native_broker_session(
    handle: NativeContainerHandle,
    *,
    run_id: str | None = None,
    token_id: str | None = None,
    nonce: str | None = None,
) -> BrokerSession:
    """Attach the existing broker state machine to process stdin/stdout."""
    identity = handle.spec.identity
    return BrokerSession(
        handle.duplex,
        run_id=run_id or identity.run_id,
        token_id=token_id or identity.token_id,
        nonce=nonce or identity.nonce,
        max_bytes=MAX_FRAME_BYTES,
    )


class NativeContainerAdapter:
    """Execute one stdio-framed native container with governed cleanup.

    The adapter is single-run: ``launch`` and ``execute`` reject a second
    concurrent run with ``NativeContainerError`` and ``execute`` always clears
    the active handle in its ``finally`` block, so one adapter instance can
    never interleave two governed runs.
    """

    def __init__(
        self,
        *,
        popen: PopenFactory = _default_popen,
        clock: Clock = time.monotonic,
        max_output_bytes: int = MAX_STDIO_BYTES,
        stop_timeout: float = 5.0,
        image_exists: Callable[[str], bool] | None = None,
        revocation_hook: Hook | None = None,
        wipe_hook: Hook | None = None,
    ) -> None:
        if max_output_bytes <= 0 or max_output_bytes > MAX_STDIO_BYTES:
            raise NativeContainerError("max_output_bytes is outside the stdio limit")
        if stop_timeout <= 0:
            raise NativeContainerError("stop_timeout must be positive")
        self._popen = popen
        self._clock = clock
        self._max_output_bytes = max_output_bytes
        self._stop_timeout = stop_timeout
        self._image_exists = image_exists
        self._revocation_hook = revocation_hook
        self._wipe_hook = wipe_hook
        self._active_handle: NativeContainerHandle | None = None
        self._active_broker: BrokerSession | None = None
        self._active_lock = threading.RLock()

    @property
    def active(self) -> bool:
        with self._active_lock:
            return self._active_handle is not None

    @property
    def stop_handle(self) -> StopHandle | None:
        """Return the active governed stop handle, if a run is active."""
        with self._active_lock:
            handle = self._active_handle
        if handle is None:
            return None
        return StopHandle(handle.spec.identity.run_id, self.stop)

    def build_argv(self, spec: NativeContainerSpec) -> list[str]:
        return build_native_container_argv(spec)

    def launch(self, spec: NativeContainerSpec) -> NativeContainerHandle:
        with self._active_lock:
            if self._active_handle is not None:
                raise NativeContainerError("a native container run is already active")
            handle = launch_native_container(
                spec,
                popen=self._popen,
                max_output_bytes=self._max_output_bytes,
                revocation_hook=self._revocation_hook,
                wipe_hook=self._wipe_hook,
                image_exists=self._image_exists,
            )
            self._active_handle = handle
            return handle

    def stop(self, reason: str = "operator_stop") -> None:
        """Request guest stop, then terminate/kill and invoke cleanup hooks."""
        if not isinstance(reason, str) or not reason:
            raise NativeContainerError("stop reason is required")
        with self._active_lock:
            handle = self._active_handle
            broker = self._active_broker
        if handle is None:
            raise NativeContainerError("no active native container run")
        if broker is not None:
            with suppress(BaseException):
                broker.stop(reason)
        try:
            handle.terminate(timeout=self._stop_timeout)
        finally:
            handle.revoke_once(reason)
            handle.wipe_once(reason)

    def execute(
        self,
        spec: NativeContainerSpec,
        workflow: Mapping[str, object],
        inputs: Mapping[str, object],
        *,
        timeout: float | None = None,
        event_sink: Callable[[HostEvent], None] | None = None,
    ) -> NativeContainerResult:
        """Run one framed guest workflow and verify its terminal receipt.

        ``event_sink`` receives hash-bound :class:`HostEvent` records, including
        the verified terminal receipt, exactly like the microVM controller.
        The run is supervised through a host-side :class:`WorkerLifecycle` that
        revokes the token and wipes adapter-owned state on every terminal path.
        """
        if not isinstance(workflow, Mapping) or not isinstance(inputs, Mapping):
            raise NativeContainerError("workflow and inputs must be maps")
        if timeout is not None and timeout <= 0:
            raise NativeContainerError("container timeout must be positive")
        started = self._clock()
        handle = self.launch(spec)
        broker = open_native_broker_session(handle)
        with self._active_lock:
            self._active_broker = broker
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        guest_receipt: Mapping[str, object] | None = None
        result_payload: dict[str, object] | None = None
        success = False
        token_id = spec.identity.token_id
        sequence = 0

        def emit(event: HostEventName, details: Mapping[str, object]) -> None:
            nonlocal sequence
            if event_sink is None:
                return
            record = HostEvent(event, spec.identity.run_id, token_id, sequence, dict(details))
            sequence += 1
            event_sink(record)

        try:
            deadline = None if timeout is None else started + timeout
            handle.duplex.set_read_timeout(self._remaining(deadline))
            emit("supervisor", {"phase": "guest_supervisor_start", "command": list(spec.command)})
            emit("transport", {"phase": "bootstrap"})
            broker.bootstrap(spec.contract())
            emit("transport", {"phase": "ready"})
            broker.run(workflow, inputs)
            emit("transport", {"phase": "run"})
            while True:
                remaining = self._remaining(deadline)
                handle.duplex.set_read_timeout(remaining)
                if handle.process.poll() is not None:
                    raise NativeContainerError("native guest exited before a terminal result")
                try:
                    frame = broker.receive()
                except NativeContainerTimeout:
                    raise
                except TimeoutError as exc:
                    raise NativeContainerTimeout("native guest read timed out") from exc
                if frame.kind in {"stdout", "stderr"}:
                    chunk = frame.payload.get("chunk")
                    if not isinstance(chunk, str):
                        raise NativeContainerError(f"{frame.kind} frame requires a text chunk")
                    target = stdout_parts if frame.kind == "stdout" else stderr_parts
                    current = sum(len(part.encode("utf-8")) for part in target)
                    if current + len(chunk.encode("utf-8")) > self._max_output_bytes:
                        raise NativeContainerError(f"guest {frame.kind} exceeds bounded capture")
                    target.append(chunk)
                    handle.record_guest_output(cast(Literal["stdout", "stderr"], frame.kind), chunk)
                    emit(
                        cast(HostEventName, frame.kind),
                        {"chunk": chunk, "sequence": frame.sequence},
                    )
                elif frame.kind == "receipt":
                    if guest_receipt is not None:
                        raise NativeContainerError("duplicate guest receipt")
                    guest_receipt = dict(frame.payload)
                elif frame.kind == "result":
                    result_payload = dict(frame.payload)
                    break
            assert result_payload is not None
            result_hash = result_payload.get("result_sha256")
            expected_hash = _sha256(
                {key: value for key, value in result_payload.items() if key != "result_sha256"}
            )
            if result_hash != expected_hash:
                raise NativeContainerError("guest result hash does not match terminal payload")
            exit_status = result_payload.get("exit_status")
            if isinstance(exit_status, bool) or not isinstance(exit_status, int):
                raise NativeContainerError("guest result exit_status must be an integer")
            if guest_receipt is None:
                raise NativeContainerError("guest result is missing receipt")
            containment = self._validate_receipt(guest_receipt, spec, expected_hash)
            remaining = self._remaining(None if timeout is None else started + timeout)
            status = handle.wait(timeout=remaining)
            if status != exit_status:
                raise NativeContainerError("native process exit disagrees with guest result")
            host_output = handle.collect_output(timeout=remaining)
            stderr = "".join(stderr_parts)
            if host_output.stderr:
                stderr += host_output.stderr
            stdout = "".join(stdout_parts)
            emit(
                "output",
                {
                    "exit_status": exit_status,
                    "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
                    "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
                },
            )
            receipt = HostReceipt(
                run_id=spec.identity.run_id,
                token_id=token_id,
                nonce=spec.identity.nonce,
                status="success" if exit_status == 0 else "failed",
                exit_status=exit_status,
                result_sha256=expected_hash,
                guest_receipt={
                    **dict(guest_receipt),
                    **({"containment": dict(containment)} if containment is not None else {}),
                },
            )
            emit("receipt", receipt.to_dict())
            emit("supervisor", {"reason": "worker_exit", "exit_status": exit_status})
            emit("revoke", {"reason": "worker_exit"})
            emit("wipe", {"reason": "worker_exit"})
            success = True
            handle.revoke_once("worker_exit")
            handle.wipe_once("worker_exit")
            runtime_ms = max(0, int((self._clock() - started) * 1000))
            return NativeContainerResult(exit_status, stdout, stderr, runtime_ms)
        except BaseException as exc:
            self._failure_cleanup(handle, broker, exc)
            raise
        finally:
            with suppress(BaseException):
                broker.close()
            with suppress(BaseException):
                handle.cleanup()
            with self._active_lock:
                self._active_broker = None
                self._active_handle = None
            if not success:
                # ``_failure_cleanup`` is idempotent; this branch documents that
                # every non-success terminal path reaches revoke and wipe.
                with suppress(BaseException):
                    handle.revoke_once("run_failure")
                with suppress(BaseException):
                    handle.wipe_once("run_failure")

    def run(
        self,
        spec: NativeContainerSpec | None = None,
        workflow: Mapping[str, object] | None = None,
        inputs: Mapping[str, object] | None = None,
        *,
        timeout: float | None = None,
        run_id: str | None = None,
        workflow_path: Path | None = None,
        runs_dir: Path | None = None,
        isolation: IsolationProfile | None = None,
        lease_id: str | None = None,
        image_digest: str | None = None,
        inputs_dir: Path | None = None,
        cache_dir: Path | None = None,
        authorization_env: Mapping[str, str] | None = None,
        lease_path: Path | None = None,
        attestation_path: Path | None = None,
        capability_token_path: Path | None = None,
        workflow_name: str | None = None,
        event_sink: Callable[[object], None] | None = None,
    ) -> NativeContainerResult:
        """Run directly or through the generic ``RunnerController`` shape.

        The Runner-facing form intentionally rejects host control-file and
        arbitrary-environment inputs: this adapter sends only the fixed stdio
        contract and run-local storage mounts. ``event_sink`` receives the
        same hash-bound :class:`HostEvent` stream as the microVM controller.
        """
        if spec is not None:
            if workflow is None or inputs is None:
                raise NativeContainerError("workflow and inputs are required with spec")
            if any(
                value is not None
                for value in (
                    run_id,
                    workflow_path,
                    runs_dir,
                    isolation,
                    lease_id,
                    image_digest,
                    inputs_dir,
                    cache_dir,
                    authorization_env,
                    lease_path,
                    attestation_path,
                    capability_token_path,
                )
            ):
                raise NativeContainerError("spec cannot be combined with Runner fields")
            return self.execute(spec, workflow, inputs, timeout=timeout, event_sink=event_sink)
        if workflow is not None or inputs is not None:
            raise NativeContainerError("spec is required with direct workflow and inputs")
        if workflow_path is None or runs_dir is None or isolation is None:
            raise NativeContainerError("workflow_path, runs_dir and isolation are required")
        if run_id is None or lease_id is None or image_digest is None:
            raise NativeContainerError("run_id, lease_id and image_digest are required")
        if any(path is not None for path in (lease_path, attestation_path, capability_token_path)):
            raise NativeContainerError("native adapter does not mount host control files")
        if authorization_env:
            raise NativeContainerError("native adapter does not accept arbitrary environment")
        return self.run_workflow(
            workflow_path=workflow_path,
            runs_dir=runs_dir,
            isolation=isolation,
            lease_id=lease_id,
            run_id=run_id,
            image_digest=image_digest,
            inputs_dir=inputs_dir,
            cache_dir=cache_dir,
            timeout=timeout,
            event_sink=event_sink,
        )

    def run_workflow(
        self,
        *,
        workflow_path: Path,
        runs_dir: Path,
        isolation: IsolationProfile,
        lease_id: str,
        run_id: str,
        image_digest: str,
        artifact_digest: str | None = None,
        token_id: str | None = None,
        nonce: str | None = None,
        inputs_dir: Path | None = None,
        cache_dir: Path | None = None,
        timeout: float | None = None,
        command: Sequence[str] | None = None,
        authorization_env: Mapping[str, str] | None = None,
        event_sink: Callable[[HostEvent], None] | None = None,
        **unsupported: object,
    ) -> NativeContainerResult:
        """Runner-facing path that reads a workflow and never mounts its file."""
        if authorization_env:
            raise NativeContainerError(
                "native stdio mode does not accept authorization environment"
            )
        if unsupported:
            names = ", ".join(sorted(unsupported))
            raise NativeContainerError(f"unsupported native run options: {names}")
        try:
            workflow_data = json.loads(workflow_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise NativeContainerError(f"unable to read workflow JSON: {workflow_path}") from exc
        if not isinstance(workflow_data, Mapping):
            raise NativeContainerError("workflow JSON must be an object")
        digest = artifact_digest or _normalise_digest("image_digest", image_digest)
        selected_identity = NativeContainerIdentity(
            lease_id=lease_id,
            run_id=run_id,
            artifact_digest=digest,
            policy_digest=isolation.policy_digest,
            token_id=token_id or f"native-{run_id}",
            nonce=nonce or hashlib.sha256(f"{lease_id}:{run_id}:{digest}".encode()).hexdigest(),
        )
        spec = NativeContainerSpec(
            image=isolation.image,
            workspace_dir=runs_dir,
            identity=selected_identity,
            isolation=isolation,
            input_dir=inputs_dir,
            cache_dir=cache_dir,
            command=tuple(command or (_SUPERVISOR_ENTRY,)),
        )
        return self.execute(spec, workflow_data, {}, timeout=timeout, event_sink=event_sink)

    def _remaining(self, deadline: float | None) -> float | None:
        if deadline is None:
            return None
        remaining = deadline - self._clock()
        if remaining <= 0:
            raise NativeContainerTimeout("native container run timed out")
        return remaining

    def _failure_cleanup(
        self,
        handle: NativeContainerHandle,
        broker: BrokerSession,
        primary: BaseException,
    ) -> None:
        with suppress(BaseException):
            if broker.state in {"ready", "running"}:
                broker.stop("controller_failure")
        operations: tuple[tuple[str, Callable[[], None]], ...] = (
            ("terminate", lambda: handle.terminate(timeout=self._stop_timeout)),
            ("revoke", lambda: handle.revoke_once("controller_failure")),
            ("wipe", lambda: handle.wipe_once("controller_failure")),
        )
        for name, operation in operations:
            try:
                operation()
            except BaseException as cleanup_error:
                primary.add_note(
                    f"native cleanup {name} failed: {type(cleanup_error).__name__}: {cleanup_error}"
                )
        try:
            output = handle.collect_output(timeout=self._stop_timeout)
            if output.stderr:
                primary.add_note(f"native guest stderr: {output.stderr}")
        except BaseException as output_error:
            primary.add_note(
                f"native cleanup output failed: {type(output_error).__name__}: {output_error}"
            )

    @staticmethod
    def _validate_receipt(
        receipt: Mapping[str, object], spec: NativeContainerSpec, result_hash: str
    ) -> Mapping[str, object] | None:
        """Validate the guest receipt and return the bound containment evidence.

        Containment is bound exactly like :class:`HostController`: when the
        contract carries the monitor identity, the receipt must repeat that
        identity with ``monitor_active: true``; when it does not, the receipt
        must not invent containment evidence. The returned mapping is the
        validated containment block, or ``None`` when the contract is
        containment-free.
        """
        expected: dict[str, object] = {
            "schema": "testudo.guest.receipt.v1",
            "run_id": spec.identity.run_id,
            "token_id": spec.identity.token_id,
            "nonce": spec.identity.nonce,
            "result_sha256": result_hash,
            "artifact_digest": spec.identity.artifact_digest,
        }
        for field_name, value in expected.items():
            if receipt.get(field_name) != value:
                raise NativeContainerError(f"guest receipt mismatch: {field_name}")
        contract_containment = spec.contract().get("containment")
        if contract_containment is not None:
            if not isinstance(contract_containment, Mapping):
                raise NativeContainerError("native containment contract is invalid")
            expected_containment = {**dict(contract_containment), "monitor_active": True}
            if receipt.get("containment") != expected_containment:
                raise NativeContainerError("guest receipt containment identity mismatch")
            return dict(expected_containment)
        if "containment" in receipt:
            raise NativeContainerError("guest receipt contains unrequested containment evidence")
        return None


@dataclass(frozen=True, slots=True)
class NativeContainerResult:
    """Host-observed result matching the Runner result shape."""

    exit_status: int
    stdout: str
    stderr: str
    runtime_ms: int


NativeRunResult = NativeContainerResult


def run_native_container(
    spec: NativeContainerSpec,
    workflow: Mapping[str, object],
    inputs: Mapping[str, object],
    *,
    timeout: float | None = None,
    popen: PopenFactory = _default_popen,
    clock: Clock = time.monotonic,
    max_output_bytes: int = MAX_STDIO_BYTES,
    stop_timeout: float = 5.0,
    image_exists: Callable[[str], bool] | None = None,
    revocation_hook: Hook | None = None,
    wipe_hook: Hook | None = None,
) -> NativeContainerResult:
    """Convenience function for one deterministic, injected native run."""
    return NativeContainerAdapter(
        popen=popen,
        clock=clock,
        max_output_bytes=max_output_bytes,
        stop_timeout=stop_timeout,
        image_exists=image_exists,
        revocation_hook=revocation_hook,
        wipe_hook=wipe_hook,
    ).execute(spec, workflow, inputs, timeout=timeout)


__all__ = [
    "GUEST_MODE",
    "GUEST_PROTOCOL",
    "MAX_OUTPUT_BYTES",
    "MAX_STDIO_BYTES",
    "NATIVE_RUN_ID_ENV",
    "NATIVE_SUPERVISOR_ENTRY",
    "NativeContainerAdapter",
    "NativeContainerDuplex",
    "NativeContainerError",
    "NativeContainerHandle",
    "NativeContainerIdentity",
    "NativeContainerMount",
    "NativeContainerOutput",
    "NativeContainerResult",
    "NativeContainerSpec",
    "NativeContainerTimeout",
    "NativeContainerWorker",
    "NativeProcess",
    "NativeRunResult",
    "NativeVMHandle",
    "build_container_argv",
    "build_native_argv",
    "build_native_container_argv",
    "launch_native_container",
    "launch_native_worker",
    "open_native_broker_session",
    "run_native_container",
]
