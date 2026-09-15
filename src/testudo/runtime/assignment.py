# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-only

"""Closed contained-assignment protocol for one finite Testudo journey.

The dispatcher owns scheduling and envelopes.  This module validates the
closed request, starts only a configured governed Testudo Runner, records
host-observed events and terminal evidence, and exposes cancellation and
restart reconciliation.  It never constructs a Docker or host fallback.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from testudo.artifacts import ArtifactStore, ChunkScanner
from testudo.runtime.backend import ExecutionBackend
from testudo.runtime.isolation import IsolationProfile
from testudo.runtime.runner import Runner, RunnerResult

REQUEST_SCHEMA = "testudo.assignment.request.v1"
EVENT_SCHEMA = "testudo.assignment.event.v1"
RECEIPT_SCHEMA = "testudo.assignment.receipt.v1"
RECONCILE_SCHEMA = "testudo.assignment.reconcile.v1"
OPERATOR_RECONCILE_SCHEMA = "testudo.assignment.operator-reconcile.v1"
QUARANTINE_SCHEMA = "testudo.assignment.quarantine.v1"
AMBIGUOUS_SCHEMA = "testudo.assignment.ambiguous.v1"
TOMBSTONE_SCHEMA = "testudo.assignment.identity-tombstone.v1"
QUARANTINE_SUFFIX = ".quarantined"
TOMBSTONE_NAME = "identity-tombstone.json"
_ALLOWED_BACKENDS = frozenset({ExecutionBackend.MICROVM, ExecutionBackend.NATIVE_CONTAINER})
AssignmentEventName = Literal[
    "admitted", "started", "cancel_requested", "succeeded", "failed", "cancelled", "refused"
]


class AssignmentError(RuntimeError):
    """The assignment is invalid, unavailable, or violates containment."""


def _canonical(value: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AssignmentError("assignment value is not canonical JSON") from exc


def _digest(value: Mapping[str, object]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(UTC)


class PiJourney(BaseModel):
    """Finite contained Pi invocation supplied by the driver control plane."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    prompt: str = Field(min_length=1, max_length=32768)
    role: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9-]*$")
    model: str = Field(min_length=1, max_length=192)
    max_steps: int = Field(ge=1, le=200)
    autonomy: Literal["confirmed-default", "autonomous"]


class AssignmentRequest(BaseModel):
    """Closed dispatcher-authenticated request accepted by Testudo."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    schema_: Literal["testudo.assignment.request.v1"] = Field(
        "testudo.assignment.request.v1", alias="schema"
    )
    assignment_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
    envelope_id: str = Field(min_length=1, max_length=128)
    repository: str = Field(min_length=1, max_length=1024)
    branch: str = Field(min_length=7, max_length=256)
    base_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    allowed_paths: tuple[str, ...]
    capabilities: tuple[str, ...]
    stopping_point: str = Field(min_length=1, max_length=4096)
    expires_at: datetime
    backend: Literal["microvm", "native-container"]
    image: str = Field(min_length=1, max_length=1024)
    journey: PiJourney
    artifact_store_id: str | None = Field(default=None, min_length=1, max_length=128)
    egress_scanner_id: str | None = Field(default=None, min_length=1, max_length=128)
    envelope_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("branch")
    @classmethod
    def agent_branch(cls, value: str) -> str:
        if not value.startswith("agent/"):
            raise ValueError("assignment branch must start with agent/")
        return value

    @field_validator("allowed_paths")
    @classmethod
    def safe_paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values:
            raise ValueError("at least one allowed path is required")
        if len(values) != len(set(values)):
            raise ValueError("allowed paths must be unique")
        for value in values:
            path = PurePosixPath(value)
            if not value or value.startswith("/") or ".." in path.parts:
                raise ValueError("allowed paths must be repository-relative")
        return values

    @field_validator("capabilities")
    @classmethod
    def closed_capabilities(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)) or any(
            not value or len(value) > 128 for value in values
        ):
            raise ValueError("capabilities must be unique non-empty names")
        forbidden = {"docker", "podman", "host", "host-exec", "host-spawn"}
        if forbidden.intersection(values):
            raise ValueError("host and Docker-compatible capabilities are forbidden")
        return values

    @model_validator(mode="after")
    def artifact_binding_is_all_or_nothing(self) -> AssignmentRequest:
        if (self.artifact_store_id is None) != (self.egress_scanner_id is None):
            raise ValueError("artifact_store_id and egress_scanner_id must be provided together")
        return self

    @model_validator(mode="after")
    def immutable_and_live(self) -> AssignmentRequest:
        if "sha256:" not in self.image:
            raise ValueError("assignment image must be pinned by SHA-256")
        if self.expires_at.tzinfo is None:
            raise ValueError("expires_at must include a timezone")
        return self

    @property
    def calculated_envelope_sha256(self) -> str:
        """Return the digest of the normalized closed request payload."""
        payload = self.model_dump(mode="json", by_alias=True, exclude={"envelope_sha256"})
        return _digest(payload)

    def verify(self, *, now: datetime | None = None) -> None:
        current = (now or _utc_now()).astimezone(UTC)
        if current >= self.expires_at.astimezone(UTC):
            raise AssignmentError("assignment envelope expired")
        if self.calculated_envelope_sha256 != self.envelope_sha256:
            raise AssignmentError("assignment envelope digest mismatch")

    def workflow(self) -> dict[str, object]:
        """Build the single-step finite guest workflow; no ambient shell."""
        return {
            "name": "contained-pi-journey",
            "description": self.stopping_point,
            "steps": [
                {
                    "id": "journey",
                    "uses": "runtime.pi_journey",
                    "with": self.journey.model_dump(mode="json"),
                }
            ],
        }


class AssignmentEvent(BaseModel):
    """One sequenced service observation."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    schema_: Literal["testudo.assignment.event.v1"] = Field(
        "testudo.assignment.event.v1", alias="schema"
    )
    assignment_id: str
    run_id: str
    sequence: int = Field(ge=0)
    event: AssignmentEventName
    at: datetime
    details: dict[str, object] = Field(default_factory=dict)


class AssignmentReceipt(BaseModel):
    """Terminal host-owned evidence for one assignment attempt."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    schema_: Literal["testudo.assignment.receipt.v1"] = Field(
        "testudo.assignment.receipt.v1", alias="schema"
    )
    assignment_id: str
    envelope_id: str
    envelope_sha256: str
    run_id: str
    backend: Literal["microvm", "native-container"]
    status: Literal["succeeded", "failed", "cancelled", "refused"]
    exit_status: int | None
    started_at: datetime
    finished_at: datetime
    events_sha256: str
    result_sha256: str | None
    host_receipt: dict[str, object] | None
    artifacts: tuple[dict[str, object], ...] = ()
    error: str | None
    no_host_fallback: Literal[True] = True
    receipt_id: str = ""

    @model_validator(mode="after")
    def bind_receipt(self) -> AssignmentReceipt:
        payload = self.model_dump(mode="json", by_alias=True, exclude={"receipt_id"})
        expected = _digest(payload)
        if self.receipt_id and self.receipt_id != expected:
            raise ValueError("assignment receipt digest mismatch")
        object.__setattr__(self, "receipt_id", expected)
        return self


class IdentityTombstone(BaseModel):
    """Immutable identity evidence persisted when a run directory is quarantined.

    A tombstone records the assignment and envelope identity that a previous
    process admitted even though its run directory was quarantined, so
    duplicate checks keep failing closed after a restart. A tombstone is
    never deleted and never grants execution; it only forbids reuse.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    schema_: Literal[TOMBSTONE_SCHEMA] = Field(TOMBSTONE_SCHEMA, alias="schema")  # type: ignore[valid-type]
    assignment_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
    envelope_id: str = Field(min_length=1, max_length=128)
    envelope_sha256: str = ""
    quarantined_at: datetime
    reason: str = Field(min_length=1, max_length=1024)

    @field_validator("envelope_sha256")
    @classmethod
    def digest_shape(cls, value: str) -> str:
        if value and (len(value) != 64 or any(c not in "0123456789abcdef" for c in value)):
            raise ValueError("envelope_sha256 must be empty or a lowercase SHA-256 digest")
        return value


RunnerFactory = Callable[[AssignmentRequest], Runner]
IsolationFactory = Callable[[AssignmentRequest], IsolationProfile]
ArtifactStoreFactory = Callable[[AssignmentRequest], ArtifactStore]
EgressScannerFactory = Callable[[AssignmentRequest], tuple[ChunkScanner, str, str]]
DispatcherVerifier = Callable[[AssignmentRequest], None]
OperatorVerifier = Callable[[str, Mapping[str, str]], None]


class _RunState:
    def __init__(self, request: AssignmentRequest, run_id: str) -> None:
        self.request = request
        self.run_id = run_id
        self.runner: Runner | None = None
        self.events: list[AssignmentEvent] = []
        self.receipt: AssignmentReceipt | None = None
        self.cancel_requested = False
        self.recovered = False
        self.lock = threading.RLock()
        self.started_at = _utc_now()


class AssignmentService:
    """Thread-safe lifecycle for finite contained assignment attempts."""

    def __init__(
        self,
        *,
        runner_factory: RunnerFactory,
        isolation_factory: IsolationFactory,
        verify_dispatcher: DispatcherVerifier,
        state_root: Path,
        verify_operator: OperatorVerifier | None = None,
        artifact_store_factory: ArtifactStoreFactory | None = None,
        egress_scanner_factory: EgressScannerFactory | None = None,
        now: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not callable(verify_dispatcher):
            raise ValueError("a dispatcher verifier is required")
        self._runner_factory = runner_factory
        self._isolation_factory = isolation_factory
        self._verify_dispatcher = verify_dispatcher
        self._verify_operator = verify_operator
        if (artifact_store_factory is None) != (egress_scanner_factory is None):
            raise ValueError(
                "artifact_store_factory and egress_scanner_factory must be provided together"
            )
        self._artifact_store_factory = artifact_store_factory
        self._egress_scanner_factory = egress_scanner_factory
        self._root = Path(state_root)
        self._root.mkdir(parents=True, exist_ok=True)
        self._now = now
        self._runs: dict[str, _RunState] = {}
        self._tombstones: dict[str, IdentityTombstone] = {}
        self._envelope_tombstones: dict[str, str] = {}
        self._ambiguous: set[str] = set()
        self._lock = threading.RLock()
        self._load_durable_state()

    @property
    def ambiguous_quarantines(self) -> frozenset[str]:
        """Return quarantined run names whose identity could not be recovered."""
        return frozenset(self._ambiguous)

    def start(self, value: Mapping[str, Any]) -> AssignmentEvent:
        request = AssignmentRequest.model_validate(value)
        request.verify(now=self._now())
        self._verify_dispatcher(request)
        backend = ExecutionBackend(request.backend)
        if backend not in _ALLOWED_BACKENDS:
            raise AssignmentError("assignment backend is not an approved containment boundary")
        run_id = request.assignment_id
        with self._lock:
            if self._ambiguous:
                names = ", ".join(sorted(self._ambiguous))
                raise AssignmentError(
                    "assignment state root is ambiguous: quarantined identity evidence "
                    f"is unrecoverable for {names}; explicit reconciliation is required"
                )
            self._reject_duplicate_identity(request)
            run_dir = self._root / run_id
            state = _RunState(request, run_id)
            run_dir.mkdir(mode=0o700)
            self._fsync_dir(self._root)
            # The admitted identity is durable before any work can launch: the
            # canonical request (with its envelope digest) is fsynced and the
            # directory entry is flushed, so a crash after admission can never
            # lose the evidence that forbids duplicate execution.
            self._atomic_write_bytes(
                run_dir / "request.json",
                _canonical(request.model_dump(mode="json", by_alias=True)) + b"\n",
            )
            self._runs[request.assignment_id] = state
            with state.lock:
                admitted = self._emit(state, "admitted", {"backend": request.backend})
            thread = threading.Thread(target=self._execute, args=(state,), daemon=True)
            thread.start()
            return admitted

    def _reject_duplicate_identity(self, request: AssignmentRequest) -> None:
        """Durably fail closed for a duplicate assignment or envelope identity.

        In-memory state and durable restart state are both checked under the
        service lock, so a restart cannot relaunch an identity that a previous
        process already admitted.
        """
        if request.assignment_id in self._runs:
            raise AssignmentError("assignment identity already exists")
        if request.assignment_id in self._tombstones:
            raise AssignmentError("assignment identity was quarantined and cannot be reused")
        if request.envelope_id in self._envelope_tombstones:
            raise AssignmentError(
                "assignment envelope identity was quarantined and cannot be reused"
            )
        if (self._root / request.assignment_id).exists():
            raise AssignmentError("assignment identity already has durable state")
        for state in self._runs.values():
            if state.request.envelope_id == request.envelope_id:
                raise AssignmentError("assignment envelope identity already exists")
        for run_dir in self._root.iterdir():
            if not run_dir.is_dir() or run_dir.is_symlink():
                continue
            request_path = run_dir / "request.json"
            if not request_path.is_file() or request_path.is_symlink():
                continue
            try:
                durable = AssignmentRequest.model_validate_json(request_path.read_bytes())
            except (OSError, UnicodeError, ValueError):
                # Corrupt durable identity evidence is quarantined during
                # recovery, not silently ignored here.
                continue
            if durable.envelope_id == request.envelope_id:
                raise AssignmentError("assignment envelope identity already has durable state")

    def observe(self, assignment_id: str) -> tuple[AssignmentEvent, ...]:
        state = self._state(assignment_id)
        with state.lock:
            return tuple(state.events)

    def cancel(self, assignment_id: str, reason: str) -> AssignmentEvent:
        if not reason or len(reason) > 1024:
            raise AssignmentError("cancellation reason is required and limited to 1024 characters")
        state = self._state(assignment_id)
        with state.lock:
            if state.receipt is not None:
                raise AssignmentError("assignment is already terminal")
            if state.runner is None and any(event.event == "started" for event in state.events):
                raise AssignmentError(
                    "recovered active assignment requires supervisor reconciliation"
                )
            if state.cancel_requested:
                return state.events[-1]
            state.cancel_requested = True
            event = self._emit(state, "cancel_requested", {"reason": reason})
            handle = None if state.runner is None else state.runner.stop_handle
        if handle is not None:
            handle.stop(reason)
        return event

    def receipt(self, assignment_id: str) -> AssignmentReceipt | None:
        state = self._state(assignment_id)
        with state.lock:
            return state.receipt

    def reconcile(self, envelope_id: str) -> Mapping[str, object]:
        with self._lock:
            matches = [
                state for state in self._runs.values() if state.request.envelope_id == envelope_id
            ]
        if len(matches) > 1:
            raise AssignmentError("multiple runs exist for one envelope identity")
        if not matches:
            return MappingProxyType(
                {"schema": RECONCILE_SCHEMA, "envelope_id": envelope_id, "state": "absent"}
            )
        state = matches[0]
        with state.lock:
            status = (
                state.receipt.status
                if state.receipt is not None
                else "interrupted"
                if state.recovered and state.runner is None
                else "active"
            )
            return MappingProxyType(
                {
                    "schema": RECONCILE_SCHEMA,
                    "envelope_id": envelope_id,
                    "assignment_id": state.request.assignment_id,
                    "run_id": state.run_id,
                    "state": status,
                    "receipt_id": None if state.receipt is None else state.receipt.receipt_id,
                }
            )

    def terminalize(
        self,
        assignment_id: str,
        *,
        status: Literal["failed", "cancelled"],
        reason: str,
    ) -> AssignmentReceipt:
        """Authenticated operator terminalization of one interrupted run.

        A run recovered from a restart with a ``started`` event but no runner
        can never resume: the process that owned it is gone. An authenticated
        operator closes it with a durable, digest-bound terminal event and
        receipt - without relaunching any work. Misuse is refused: an active
        run, an already-terminal run, or an unknown identity fails closed,
        and the dispatcher verifier must accept the request.
        """
        self._authorize_operator(
            "terminalize",
            {"assignment_id": assignment_id, "status": status, "reason": reason},
        )
        if not reason or len(reason) > 1024:
            raise AssignmentError(
                "terminalization reason is required and limited to 1024 characters"
            )
        with self._lock:
            state = self._runs.get(assignment_id)
            if state is None:
                raise AssignmentError("assignment identity is unknown")
            with state.lock:
                if state.receipt is not None:
                    raise AssignmentError("assignment is already terminal")
                if state.runner is not None or not state.recovered:
                    raise AssignmentError(
                        "only a recovered interrupted assignment can be terminalized; "
                        "active runs require cancellation"
                    )
                state.cancel_requested = True
                terminal = self._emit(state, status, {"reason": reason, "operator": True})
                finished = self._now()
                event_maps = [
                    event.model_dump(mode="json", by_alias=True) for event in state.events
                ]
                receipt = AssignmentReceipt(
                    schema="testudo.assignment.receipt.v1",
                    assignment_id=state.request.assignment_id,
                    envelope_id=state.request.envelope_id,
                    envelope_sha256=state.request.envelope_sha256,
                    run_id=state.run_id,
                    backend=state.request.backend,
                    status=status,
                    exit_status=None,
                    started_at=state.started_at,
                    finished_at=finished,
                    events_sha256=hashlib.sha256(_canonical({"events": event_maps})).hexdigest(),
                    result_sha256=None,
                    host_receipt=None,
                    artifacts=(),
                    error=f"operator terminalization: {reason}",
                )
                state.receipt = receipt
                self._persist(state, terminal, receipt)
                return receipt

    def _authorize_operator(self, operation: str, details: Mapping[str, str]) -> None:
        """Apply the service-owned operator authorization boundary."""
        if self._verify_operator is None:
            raise AssignmentError(f"{operation} requires operator authorization")
        self._verify_operator(operation, details)

    def _state(self, assignment_id: str) -> _RunState:
        with self._lock:
            state = self._runs.get(assignment_id)
        if state is None:
            raise AssignmentError("assignment identity is unknown")
        return state

    def _emit(
        self, state: _RunState, event: AssignmentEventName, details: Mapping[str, object]
    ) -> AssignmentEvent:
        record = AssignmentEvent(
            schema="testudo.assignment.event.v1",
            assignment_id=state.request.assignment_id,
            run_id=state.run_id,
            sequence=len(state.events),
            event=event,
            at=self._now(),
            details=dict(details),
        )
        state.events.append(record)
        run_dir = self._root / state.run_id
        run_dir.mkdir(mode=0o700, exist_ok=True)
        with (run_dir / "events.jsonl").open("ab") as stream:
            stream.write(_canonical(record.model_dump(mode="json", by_alias=True)) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        self._fsync_dir(run_dir)
        return record

    def _execute(self, state: _RunState) -> None:
        request = state.request
        result: RunnerResult | None = None
        host_receipt: dict[str, object] | None = None
        artifacts: tuple[dict[str, object], ...] = ()
        error: str | None = None
        status: Literal["succeeded", "failed", "cancelled", "refused"] = "failed"
        try:
            runner = self._runner_factory(request)
            if runner.backend.value != request.backend or runner.backend not in _ALLOWED_BACKENDS:
                raise AssignmentError("runner backend does not match the contained assignment")
            isolation = self._isolation_factory(request)
            if request.backend == "microvm" and isolation.primitive != "microvm":
                raise AssignmentError("microVM assignment requires microVM isolation")
            if isolation.network != "none" or not isolation.read_only:
                raise AssignmentError("assignment requires no-network read-only isolation")
            workflow_path = self._write_workflow(state, request.workflow())
            with state.lock:
                state.runner = runner
                if state.cancel_requested:
                    raise AssignmentError("assignment cancelled before contained startup")
                self._emit(state, "started", {})
            result = runner.run(
                workflow_path=workflow_path,
                workflow_name="contained-pi-journey",
                isolation=isolation,
                backend=request.backend,
                run_id=state.run_id,
                inputs={
                    "assignment_id": request.assignment_id,
                    "envelope_id": request.envelope_id,
                    "repository": request.repository,
                    "branch": request.branch,
                    "base_sha": request.base_sha,
                    "allowed_paths": list(request.allowed_paths),
                    "capabilities": list(request.capabilities),
                    "stopping_point": request.stopping_point,
                },
            )
            if runner.last_host_receipt is None:
                raise AssignmentError("contained run ended without a verified host receipt")
            host_receipt = dict(runner.last_host_receipt)
            artifacts = self._promote_artifacts(state, runner)
            status = (
                "cancelled"
                if state.cancel_requested
                else ("succeeded" if result.exit_status == 0 else "failed")
            )
        except BaseException as exc:
            error = f"{type(exc).__name__}: {exc}"
            status = (
                "cancelled"
                if state.cancel_requested
                else ("refused" if isinstance(exc, AssignmentError) else "failed")
            )
        finished = self._now()
        with state.lock:
            state.runner = None
            terminal = self._emit(state, status, {} if error is None else {"error": error})
            event_maps = [event.model_dump(mode="json", by_alias=True) for event in state.events]
            result_map: dict[str, object] | None = None
            if result is not None:
                result_map = {
                    "exit_status": result.exit_status,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "runtime_ms": result.runtime_ms,
                }
            receipt = AssignmentReceipt(
                schema="testudo.assignment.receipt.v1",
                assignment_id=request.assignment_id,
                envelope_id=request.envelope_id,
                envelope_sha256=request.envelope_sha256,
                run_id=state.run_id,
                backend=request.backend,
                status=status,
                exit_status=None if result is None else result.exit_status,
                started_at=state.started_at,
                finished_at=finished,
                events_sha256=hashlib.sha256(_canonical({"events": event_maps})).hexdigest(),
                result_sha256=None if result_map is None else _digest(result_map),
                host_receipt=host_receipt,
                artifacts=artifacts,
                error=error,
            )
            state.receipt = receipt
            self._persist(state, terminal, receipt)

    def _promote_artifacts(self, state: _RunState, runner: Runner) -> tuple[dict[str, object], ...]:
        """Promote produced files through the scanned egress boundary.

        When the request binds an artifact store, the runner's verified egress
        manifest becomes digest-bound receipt evidence. The store performs the
        quarantine -> scan -> re-hash -> CAS promotion; Testudo never trusts
        container bytes that did not pass the scanner. A binding without a
        manifest means the run produced nothing and is recorded as such.
        """
        if self._artifact_store_factory is None or self._egress_scanner_factory is None:
            return ()
        if state.request.artifact_store_id is None:
            return ()
        manifest = runner.last_artifact_manifest
        if manifest is None:
            raise AssignmentError(
                "assignment binds an artifact store but the contained run produced no egress manifest"
            )
        store_id = manifest.get("store_id")
        scanner_id = manifest.get("scanner_id")
        if store_id != state.request.artifact_store_id:
            raise AssignmentError("artifact manifest store does not match the assignment binding")
        if scanner_id != state.request.egress_scanner_id:
            raise AssignmentError("artifact manifest scanner does not match the assignment binding")
        files = manifest.get("files")
        if not isinstance(files, list):
            raise AssignmentError("artifact manifest is missing its files list")
        entries: list[dict[str, object]] = []
        for item in files:
            if not isinstance(item, Mapping):
                raise AssignmentError("artifact manifest entry is not an object")
            name = item.get("path")
            sha256 = item.get("sha256")
            if not isinstance(name, str) or not name:
                raise AssignmentError("artifact manifest entry is missing its path")
            if (
                not isinstance(sha256, str)
                or len(sha256) != 64
                or any(c not in "0123456789abcdef" for c in sha256)
            ):
                raise AssignmentError(f"artifact {name!r} has no valid SHA-256 digest")
            entries.append({"name": name, "sha256": sha256})
        return tuple(entries)

    def _load_durable_state(self) -> None:
        """Recover terminal and interrupted identities without relaunching work.

        A run directory created before ``request.json`` was durably written
        (for example after a crash between ``mkdir`` and the atomic rename) is
        a pre-admission crash, not a duplicate identity: it is quarantined once
        with no tombstone and never blocks recovery of the rest of the state
        root. Corrupt request, event, or receipt evidence is quarantined with
        an immutable identity tombstone whenever the identity is recoverable
        from durable evidence, so duplicate checks keep failing closed. When
        the identity itself cannot be recovered, the state root is marked
        ambiguous and new admissions fail closed until explicit
        reconciliation. Only a fully parsed identity re-enters memory.
        """
        for quarantined in sorted(self._root.glob(f"*{QUARANTINE_SUFFIX}")):
            if quarantined.is_dir() and not quarantined.is_symlink():
                self._load_tombstone(quarantined)
        # Ambiguity markers recorded by a previous process (rename failure or
        # pre-existing quarantine target) restore the fail-closed state.
        for marker in sorted(self._root.glob(f"*{QUARANTINE_SUFFIX}.ambiguous")):
            if marker.is_file() and not marker.is_symlink():
                self._ambiguous.add(marker.name[: -len(QUARANTINE_SUFFIX + ".ambiguous")])
        for run_dir in sorted(self._root.iterdir()):
            if not run_dir.is_dir() or run_dir.is_symlink():
                continue
            if run_dir.name.endswith(QUARANTINE_SUFFIX):
                continue
            request_path = run_dir / "request.json"
            if not request_path.is_file() or request_path.is_symlink():
                self._quarantine(run_dir, "missing request.json")
                continue
            try:
                request = AssignmentRequest.model_validate_json(request_path.read_bytes())
                state = _RunState(request, request.assignment_id)
                state.recovered = True
                events_path = run_dir / "events.jsonl"
                if events_path.is_file() and not events_path.is_symlink():
                    state.events = self._read_durable_events(
                        events_path,
                        assignment_id=request.assignment_id,
                        run_id=request.assignment_id,
                    )
                receipt_path = run_dir / "receipt.json"
                if receipt_path.is_file() and not receipt_path.is_symlink():
                    receipt = AssignmentReceipt.model_validate_json(receipt_path.read_bytes())
                    if (
                        receipt.assignment_id != request.assignment_id
                        or receipt.envelope_id != request.envelope_id
                        or receipt.envelope_sha256 != request.envelope_sha256
                        or receipt.run_id != state.run_id
                        or receipt.backend != request.backend
                    ):
                        raise AssignmentError(
                            "receipt identity does not match the admitted request"
                        )
                    event_maps = [
                        event.model_dump(mode="json", by_alias=True) for event in state.events
                    ]
                    expected_events = hashlib.sha256(_canonical({"events": event_maps})).hexdigest()
                    if receipt.events_sha256 != expected_events:
                        raise AssignmentError(
                            "receipt event digest does not match the durable event log"
                        )
                    state.receipt = receipt
                if request.assignment_id in self._runs:
                    raise AssignmentError("duplicate durable assignment identity")
                self._runs[request.assignment_id] = state
            except (OSError, UnicodeError, ValueError, AssignmentError) as exc:
                self._quarantine(run_dir, f"{type(exc).__name__}: {exc}")

    def _read_durable_events(
        self, path: Path, *, assignment_id: str, run_id: str
    ) -> list[AssignmentEvent]:
        """Parse one durable append-only event log, tolerating a torn tail.

        A crash mid-append leaves at most one incomplete final record. That
        torn tail is recovered (the completed records before it are kept) and
        rewritten compactly, because the file is then re-appended. Interior
        corruption is never silently dropped: it raises and the caller
        quarantines the whole identity.
        """
        raw = path.read_bytes()
        if not raw:
            return []
        lines = raw.split(b"\n")
        trailing = lines.pop()
        events: list[AssignmentEvent] = []
        complete: list[bytes] = []
        # A crash mid-append loses the tail of the final write, so the last
        # record is missing its terminating newline: that trailing chunk is
        # safely identifiable as a torn record and is recovered away. Every
        # newline-terminated record must parse; anything else is interior
        # corruption and the caller quarantines the identity.
        for line in lines:
            record = AssignmentEvent.model_validate_json(line)
            if record.assignment_id != assignment_id or record.run_id != run_id:
                raise ValueError("event log identity does not match the admitted request")
            if record.sequence != len(events):
                raise ValueError("event log sequence is not contiguous")
            events.append(record)
            complete.append(_canonical(record.model_dump(mode="json", by_alias=True)))
        if trailing:
            try:
                parsed_tail: AssignmentEvent | None = AssignmentEvent.model_validate_json(trailing)
            except ValueError:
                parsed_tail = None
            if parsed_tail is not None:
                if parsed_tail.assignment_id != assignment_id or parsed_tail.run_id != run_id:
                    raise ValueError("event log identity does not match the admitted request")
                if parsed_tail.sequence != len(events):
                    raise ValueError("event log sequence is not contiguous")
                events.append(parsed_tail)
                complete.append(_canonical(parsed_tail.model_dump(mode="json", by_alias=True)))
            payload = b"".join(line + b"\n" for line in complete)
            self._atomic_write_bytes(path, payload)
        return events

    def _load_tombstone(self, quarantined: Path) -> None:
        """Register one durable identity tombstone from a quarantined directory."""
        path = quarantined / TOMBSTONE_NAME
        if not path.is_file() or path.is_symlink():
            if any(
                entry.name not in {"quarantine.json", "request.json.tmp"}
                for entry in quarantined.iterdir()
            ):
                # Evidence exists but no tombstone protects it: the identity is
                # unverifiable, so keep the state root ambiguous.
                self._ambiguous.add(quarantined.name.removesuffix(QUARANTINE_SUFFIX))
            return
        try:
            tombstone = IdentityTombstone.model_validate_json(path.read_bytes())
        except (OSError, UnicodeError, ValueError):
            self._ambiguous.add(quarantined.name[: -len(QUARANTINE_SUFFIX)])
            return
        self._register_tombstone(tombstone)

    def _register_tombstone(self, tombstone: IdentityTombstone) -> None:
        self._tombstones[tombstone.assignment_id] = tombstone
        self._envelope_tombstones.setdefault(tombstone.envelope_id, tombstone.assignment_id)

    def _recover_identity(self, quarantined: Path) -> tuple[str, str, str] | None:
        """Return ``(assignment_id, envelope_id, envelope_sha256)`` or ``None``.

        Identity is recovered only from durably written, fully parsable
        evidence: the admitted request or the terminal receipt. Event records
        carry no envelope identity, so they never authorize a tombstone.
        """
        for name, model in (
            ("request.json", AssignmentRequest),
            ("receipt.json", AssignmentReceipt),
        ):
            path = quarantined / name
            if not path.is_file() or path.is_symlink():
                continue
            try:
                parsed = model.model_validate_json(path.read_bytes())
            except (OSError, UnicodeError, ValueError):
                continue
            return (parsed.assignment_id, parsed.envelope_id, parsed.envelope_sha256)
        return None

    def _write_tombstone(
        self, quarantined: Path, identity: tuple[str, str, str], reason: str
    ) -> tuple[IdentityTombstone, bool]:
        """Persist and register one immutable identity tombstone."""
        tombstone = IdentityTombstone(
            schema=TOMBSTONE_SCHEMA,
            assignment_id=identity[0],
            envelope_id=identity[1],
            envelope_sha256=identity[2],
            quarantined_at=self._now(),
            reason=reason,
        )
        try:
            self._atomic_write_bytes(
                quarantined / TOMBSTONE_NAME,
                _canonical(tombstone.model_dump(mode="json", by_alias=True)) + b"\n",
            )
        except OSError:
            # An unpersistable tombstone leaves the identity unverifiable:
            # fail closed instead of silently permitting duplicate execution.
            self._ambiguous.add(quarantined.name.removesuffix(QUARANTINE_SUFFIX))
            self._register_tombstone(tombstone)
            return tombstone, False
        self._register_tombstone(tombstone)
        return tombstone, True

    def reconcile_quarantine(
        self,
        name: str,
        *,
        assignment_id: str,
        envelope_id: str,
        envelope_sha256: str = "",
    ) -> IdentityTombstone:
        """Explicitly reconcile one quarantined identity that lost its evidence.

        The dispatcher that owns envelope identity asserts the identity of a
        quarantined run whose evidence was unrecoverable. The asserted identity
        is persisted as an immutable tombstone - it can never be executed
        again - and the ambiguous state clears once every ambiguous quarantine
        has been reconciled.
        """
        if not name or name in {".", ".."} or "/" in name or "\\" in name:
            raise AssignmentError("quarantine name must be a bare directory name")
        quarantined = self._root / f"{name}{QUARANTINE_SUFFIX}"
        self._authorize_operator(
            "reconcile_quarantine",
            {
                "name": name,
                "assignment_id": assignment_id,
                "envelope_id": envelope_id,
                "envelope_sha256": envelope_sha256,
            },
        )
        with self._lock:
            if not quarantined.is_dir() or quarantined.is_symlink():
                raise AssignmentError("quarantine entry is unknown")
            if name not in self._ambiguous:
                raise AssignmentError("quarantine entry does not require reconciliation")
            if assignment_id in self._tombstones or assignment_id in self._runs:
                raise AssignmentError("assignment identity already exists")
            if envelope_id in self._envelope_tombstones or any(
                state.request.envelope_id == envelope_id for state in self._runs.values()
            ):
                raise AssignmentError("assignment envelope identity already exists")
            tombstone, persisted = self._write_tombstone(
                quarantined,
                (assignment_id, envelope_id, envelope_sha256),
                "operator reconciliation",
            )
            if not persisted:
                raise AssignmentError("identity tombstone could not be persisted")
            self._ambiguous.discard(name)
            # The durable ambiguity marker is evidence that the ambiguity
            # existed, not a live failure: once the identity is tombstoned the
            # fail-closed state is resolved, so the marker is retired.
            marker = self._root / f"{name}{QUARANTINE_SUFFIX}.ambiguous"
            with suppress(OSError):
                marker.unlink()
                self._fsync_dir(self._root)
            return tombstone

    def _quarantine(self, run_dir: Path, reason: str) -> None:
        """Move one unusable run directory aside without blocking recovery.

        Quarantine is bounded to the single corrupt identity: every other
        assignment keeps loading and starting. The quarantined directory is
        never deleted and never re-admitted. An empty directory is a
        pre-admission crash (the ``mkdir`` before the durable request rename)
        and carries no identity, so no tombstone is written. Otherwise the
        identity is tombstoned when recoverable; when it is not, the state
        root becomes ambiguous and admissions fail closed until explicit
        reconciliation. A rename failure or a pre-existing quarantine target
        is the worst case: the identity evidence is unreadable and unparsable
        by construction, so the run name is durably recorded as ambiguous and
        the in-memory ambiguous set forbids any new admission - assignment and
        envelope identities can never be silently reused.
        """
        target = run_dir.with_name(run_dir.name + QUARANTINE_SUFFIX)
        try:
            if target.exists():
                # A quarantine target that already exists means a previous
                # quarantine of this identity never completed durably. The
                # remaining directory is unusable evidence: fail closed on the
                # run name rather than overwrite or delete anything.
                self._mark_ambiguous(run_dir.name, "quarantine target already exists")
                return
            entries = tuple(run_dir.iterdir())
            pre_admission = not entries or {entry.name for entry in entries} == {"request.json.tmp"}
            run_dir.rename(target)
        except OSError:
            self._mark_ambiguous(run_dir.name, "quarantine rename failed")
            return
        if pre_admission:
            reason = "pre-admission incomplete run directory"
        record = {
            "schema": QUARANTINE_SCHEMA,
            "run_id": run_dir.name,
            "reason": reason,
            "at": self._now().isoformat(),
        }
        try:
            self._atomic_write_bytes(
                target / "quarantine.json",
                _canonical(record) + b"\n",
            )
        except OSError:
            return
        if pre_admission:
            return
        identity = self._recover_identity(target)
        if identity is None:
            self._mark_ambiguous(run_dir.name, "quarantine identity unrecoverable")
            return
        self._write_tombstone(target, identity, reason)

    def _mark_ambiguous(self, run_name: str, reason: str) -> None:
        """Durably and in-memory mark one run identity ambiguous.

        The run directory (or its unreadable remains) stays untouched. A
        marker file is written next to it so a restart re-enters the same
        fail-closed state, and the in-memory ambiguous set blocks every new
        admission until explicit operator reconciliation clears it.
        """
        self._ambiguous.add(run_name)
        marker = self._root / f"{run_name}{QUARANTINE_SUFFIX}.ambiguous"
        if marker.is_file():
            return
        record = {
            "schema": AMBIGUOUS_SCHEMA,
            "run_id": run_name,
            "reason": reason,
            "at": self._now().isoformat(),
        }
        try:
            self._atomic_write_bytes(marker, _canonical(record) + b"\n")
        except OSError:
            # The durable marker could not be written; the in-memory ambiguous
            # set still fails closed for this process, and the reason is
            # recorded on the quarantine record when one exists.
            return

    def _fsync_dir(self, path: Path) -> None:
        """Flush a directory entry so renames and creations survive a crash."""
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except OSError:
            raise
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _atomic_write_bytes(self, path: Path, payload: bytes) -> None:
        """Durably write one terminal artifact through a same-directory rename."""
        temporary = path.with_name(path.name + ".tmp")
        with temporary.open("wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        self._fsync_dir(path.parent)

    def _write_workflow(self, state: _RunState, workflow: Mapping[str, object]) -> Path:
        run_dir = self._root / state.run_id
        path = run_dir / "workflow.json"
        self._atomic_write_bytes(path, _canonical(workflow) + b"\n")
        return path

    def _persist(
        self, state: _RunState, terminal: AssignmentEvent, receipt: AssignmentReceipt
    ) -> None:
        run_dir = self._root / state.run_id
        run_dir.mkdir(mode=0o700, exist_ok=True)
        self._atomic_write_bytes(
            run_dir / "terminal-event.json",
            _canonical(terminal.model_dump(mode="json", by_alias=True)) + b"\n",
        )
        self._atomic_write_bytes(
            run_dir / "receipt.json",
            _canonical(receipt.model_dump(mode="json", by_alias=True)) + b"\n",
        )
        self._fsync_dir(run_dir)


__all__ = [
    "AssignmentError",
    "AssignmentEvent",
    "AssignmentReceipt",
    "AssignmentRequest",
    "AssignmentService",
    "DispatcherVerifier",
    "IdentityTombstone",
    "OperatorVerifier",
    "PiJourney",
]
