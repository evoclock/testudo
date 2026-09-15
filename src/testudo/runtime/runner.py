# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Host-side runner for one isolated Testudo workflow.

The container receives only a controller-created exchange directory.  The
host-owned audit log is outside that mount.  Governed callers can provide an
:class:`~testudo.artifacts.ArtifactStore` and scanner; output is then promoted
only through the scanned egress importer after the container exits.
"""

from __future__ import annotations

import json
import re
import threading
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Protocol, runtime_checkable

from testudo.artifacts import ArtifactStore, ChunkScanner
from testudo.audit import AuditEvent, AuditLog
from testudo.runtime import docker
from testudo.runtime.attestation import issue_attestation, write_attestation
from testudo.runtime.backend import ExecutionBackend, coerce_backend
from testudo.runtime.controller import HostEvent, StopHandle
from testudo.runtime.isolation import IsolationProfile


@dataclass(frozen=True, slots=True)
class RunnerAuthorization:
    """Per-run authority inputs owned by the configured host supervisor."""

    lease_path: Path
    capability_token_path: Path
    authorization_env: Mapping[str, str]
    lease_id: str
    image_digest: str


RunnerAuthorizationProvider = Callable[[str], RunnerAuthorization]


@runtime_checkable
class RunnerResult(Protocol):
    """Backend-neutral host-observed execution result."""

    @property
    def exit_status(self) -> int: ...

    @property
    def stdout(self) -> str: ...

    @property
    def stderr(self) -> str: ...

    @property
    def runtime_ms(self) -> int: ...


class RunnerController(Protocol):
    """Runner-facing adapter for one governed host execution boundary."""

    @property
    def stop_handle(self) -> StopHandle | None:
        """Return the active governed stop handle, if one exists."""

    def run(
        self,
        *,
        run_id: str,
        workflow_path: Path,
        workflow_name: str,
        runs_dir: Path,
        isolation: IsolationProfile,
        inputs_dir: Path | None,
        timeout: float | None,
        lease_path: Path | None,
        lease_id: str | None,
        attestation_path: Path | None,
        capability_token_path: Path | None,
        authorization_env: Mapping[str, str] | None,
        image_digest: str | None,
        event_sink: Callable[[HostEvent], None],
    ) -> RunnerResult:
        """Execute through a host controller and emit typed runtime events."""


# Compatibility name for existing callers; new integrations use the generic
# controller protocol because microVM and native-container adapters share it.
RunnerMicroVMController = RunnerController


class Runner:
    """Coordinate audit logging and optional scanned output promotion.

    One ``Runner`` instance executes one run at a time: a second ``run`` call
    while a run is active fails closed with ``RuntimeError`` instead of
    interleaving controller state, receipts, or audit events. Create one
    Runner per concurrent run.
    """

    def __init__(
        self,
        runs_root: Path,
        *,
        backend: ExecutionBackend | str = ExecutionBackend.MICROVM,
        microvm_invoke: Callable[..., docker.RunResult] | None = None,
        microvm_controller: RunnerController | None = None,
        native_container_controller: RunnerController | None = None,
        authorization: RunnerAuthorization | None = None,
        authorization_provider: RunnerAuthorizationProvider | None = None,
    ) -> None:
        if microvm_invoke is not None and microvm_controller is not None:
            raise ValueError("microvm_invoke and microvm_controller are mutually exclusive")
        if authorization is not None and authorization_provider is not None:
            raise ValueError("authorization and authorization_provider are mutually exclusive")
        self.runs_root = runs_root
        self.backend = coerce_backend(backend)
        self.microvm_invoke = microvm_invoke
        self.microvm_controller = microvm_controller
        self.native_container_controller = native_container_controller
        self.authorization = authorization
        self.authorization_provider = authorization_provider
        self._active_controller: RunnerController | None = None
        self._last_host_receipt: Mapping[str, object] | None = None
        self._run_lock = threading.Lock()
        self._run_active = False
        runs_root.mkdir(parents=True, exist_ok=True)

    @property
    def last_host_receipt(self) -> Mapping[str, object] | None:
        """Return the verified host receipt from the most recent run."""
        return self._last_host_receipt

    @property
    def stop_handle(self) -> StopHandle | None:
        """Return the active governed controller's stop handle."""
        if self._active_controller is None:
            return None
        return self._active_controller.stop_handle

    def run(
        self,
        *,
        workflow_path: Path,
        workflow_name: str,
        isolation: IsolationProfile,
        backend: ExecutionBackend | str | None = None,
        run_id: str | None = None,
        inputs: Mapping[str, object] | None = None,
        inputs_dir: Path | None = None,
        timeout: float | None = None,
        artifact_store: ArtifactStore | None = None,
        egress_scanner: ChunkScanner | None = None,
        egress_scanner_id: str | None = None,
        egress_policy_hash: str | None = None,
        lease_path: Path | None = None,
        capability_token_path: Path | None = None,
        authorization_env: Mapping[str, str] | None = None,
        lease_id: str | None = None,
        image_digest: str | None = None,
        attestation_lifetime: timedelta = timedelta(minutes=30),
    ) -> RunnerResult:
        """Execute a workflow and return its result.

        When ``artifact_store`` is supplied, ``egress_scanner`` is mandatory.
        The container can write only to ``exchange``; the audit log remains
        outside the writable mount and every output file is scanned before
        promotion into the host-local CAS.

        ``microvm`` is the governed default. ``native-container`` is the explicit
        macOS boundary. Docker remains an opt-in compatibility backend and is
        never selected as a fallback for either governed boundary.
        """
        selected_backend = coerce_backend(backend or self.backend)
        with self._run_lock:
            if self._active_controller is not None or self._run_active:
                raise RuntimeError("this Runner instance already has an active run")
            self._last_host_receipt = None
            self._run_active = True
        try:
            return self._execute_run(
                workflow_path=workflow_path,
                workflow_name=workflow_name,
                isolation=isolation,
                selected_backend=selected_backend,
                run_id=run_id,
                inputs=inputs,
                inputs_dir=inputs_dir,
                timeout=timeout,
                artifact_store=artifact_store,
                egress_scanner=egress_scanner,
                egress_scanner_id=egress_scanner_id,
                egress_policy_hash=egress_policy_hash,
                lease_path=lease_path,
                capability_token_path=capability_token_path,
                authorization_env=authorization_env,
                lease_id=lease_id,
                image_digest=image_digest,
                attestation_lifetime=attestation_lifetime,
            )
        finally:
            with self._run_lock:
                self._run_active = False

    def _execute_run(
        self,
        *,
        workflow_path: Path,
        workflow_name: str,
        isolation: IsolationProfile,
        selected_backend: ExecutionBackend,
        run_id: str | None,
        inputs: Mapping[str, object] | None,
        inputs_dir: Path | None,
        timeout: float | None,
        artifact_store: ArtifactStore | None,
        egress_scanner: ChunkScanner | None,
        egress_scanner_id: str | None,
        egress_policy_hash: str | None,
        lease_path: Path | None,
        capability_token_path: Path | None,
        authorization_env: Mapping[str, str] | None,
        lease_id: str | None,
        image_digest: str | None,
        attestation_lifetime: timedelta,
    ) -> RunnerResult:
        """Execute one admitted run; ``run`` serializes single-instance use."""
        if inputs is not None and inputs_dir is not None:
            raise ValueError("inputs and inputs_dir are mutually exclusive")
        if run_id is not None and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", run_id) is None:
            raise ValueError("run_id must be 1-64 safe identifier characters")
        if (
            selected_backend is ExecutionBackend.MICROVM
            and self.microvm_invoke is None
            and self.microvm_controller is None
        ):
            raise RuntimeError("microVM backend selected but no host microVM adapter is configured")
        if (
            selected_backend is ExecutionBackend.NATIVE_CONTAINER
            and self.native_container_controller is None
        ):
            raise RuntimeError(
                "native-container backend selected but no native container adapter is configured"
            )
        run_id = run_id or uuid.uuid4().hex[:12]
        authority = (
            self.authorization_provider(run_id)
            if self.authorization_provider is not None
            else self.authorization
        )
        if authority is not None and not isinstance(authority, RunnerAuthorization):
            raise ValueError("authorization provider must return RunnerAuthorization")
        if authority is not None:
            lease_path = lease_path or authority.lease_path
            capability_token_path = capability_token_path or authority.capability_token_path
            authorization_env = authorization_env or authority.authorization_env
            lease_id = lease_id or authority.lease_id
            image_digest = image_digest or authority.image_digest
        if artifact_store is not None and (
            egress_scanner is None or not egress_scanner_id or not egress_policy_hash
        ):
            raise ValueError(
                "egress_scanner, egress_scanner_id, and egress_policy_hash are required with artifact_store"
            )
        contained = (
            lease_path is not None
            or capability_token_path is not None
            or authorization_env is not None
        )
        if contained and (
            lease_path is None
            or capability_token_path is None
            or authorization_env is None
            or not lease_id
            or not image_digest
        ):
            raise ValueError(
                "contained runs require lease_path, capability_token_path, authorization_env, lease_id, and image_digest"
            )
        if contained:
            assert image_digest is not None
            if image_digest not in isolation.image:
                raise ValueError("contained runs require an image reference pinned to image_digest")
        if selected_backend is ExecutionBackend.NATIVE_CONTAINER:
            if not lease_id or not image_digest:
                raise ValueError("native-container runs require lease_id and image_digest")
            if image_digest not in isolation.image:
                raise ValueError(
                    "native-container runs require an image reference pinned to image_digest"
                )

        run_dir = self.runs_root / run_id
        run_dir.mkdir()
        exchange_dir = run_dir / "exchange"
        exchange_dir.mkdir()
        if inputs is not None:
            input_dir = run_dir / "inputs"
            input_dir.mkdir()
            (input_dir / "inputs.json").write_text(
                json.dumps(dict(inputs), sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            inputs_dir = input_dir
        attestation_path: Path | None = None
        attestation = None
        if contained:
            assert lease_path is not None and lease_id is not None and image_digest is not None
            attestation_path = run_dir / "runtime-attestation.json"
            attestation = issue_attestation(
                lease_id=lease_id,
                run_id=run_id,
                image_digest=image_digest,
                output_exchange=exchange_dir,
                lifetime=attestation_lifetime,
            )
            write_attestation(attestation_path, attestation)

        audit = AuditLog(run_dir / "audit.jsonl")
        audit.emit(
            AuditEvent(
                type="workflow_start",
                run_id=run_id,
                workflow=workflow_name,
                args={
                    "isolation": isolation.model_dump(),
                    "policy_sha256": isolation.policy_digest,
                    "backend": selected_backend.value,
                    "contained": contained,
                    **({"attestation_hash": attestation.attestation_hash} if attestation else {}),
                },
            )
        )

        def emit_host_event(event: HostEvent) -> None:
            if event.run_id != run_id:
                raise RuntimeError("host event run_id does not match Runner run")
            if event.event == "receipt":
                self._last_host_receipt = dict(event.details)
            audit.emit(
                AuditEvent(
                    type="host_event",
                    run_id=run_id,
                    workflow=workflow_name,
                    step_id=event.event,
                    args={"host_event": event.to_dict()},
                )
            )

        result: RunnerResult
        try:
            if selected_backend is ExecutionBackend.DOCKER:
                result = docker.invoke(
                    workflow_path=workflow_path,
                    runs_dir=exchange_dir,
                    isolation=isolation,
                    inputs_dir=inputs_dir,
                    timeout=timeout,
                    lease_path=lease_path,
                    attestation_path=attestation_path,
                    capability_token_path=capability_token_path,
                    authorization_env=authorization_env,
                )
            elif selected_backend is ExecutionBackend.NATIVE_CONTAINER:
                assert self.native_container_controller is not None
                self._active_controller = self.native_container_controller
                try:
                    result = self.native_container_controller.run(
                        run_id=run_id,
                        workflow_path=workflow_path,
                        workflow_name=workflow_name,
                        runs_dir=exchange_dir,
                        isolation=isolation,
                        inputs_dir=inputs_dir,
                        timeout=timeout,
                        lease_path=None,
                        lease_id=lease_id,
                        attestation_path=None,
                        capability_token_path=None,
                        authorization_env=None,
                        image_digest=image_digest,
                        event_sink=emit_host_event,
                    )
                finally:
                    self._active_controller = None
            elif self.microvm_controller is not None:
                self._active_controller = self.microvm_controller
                try:
                    result = self.microvm_controller.run(
                        run_id=run_id,
                        workflow_path=workflow_path,
                        workflow_name=workflow_name,
                        runs_dir=exchange_dir,
                        isolation=isolation,
                        inputs_dir=inputs_dir,
                        timeout=timeout,
                        lease_path=lease_path,
                        lease_id=lease_id,
                        attestation_path=attestation_path,
                        capability_token_path=capability_token_path,
                        authorization_env=authorization_env,
                        image_digest=image_digest,
                        event_sink=emit_host_event,
                    )
                finally:
                    self._active_controller = None
            else:
                assert self.microvm_invoke is not None
                result = self.microvm_invoke(
                    workflow_path=workflow_path,
                    runs_dir=exchange_dir,
                    isolation=isolation,
                    inputs_dir=inputs_dir,
                    timeout=timeout,
                    lease_path=lease_path,
                    attestation_path=attestation_path,
                    capability_token_path=capability_token_path,
                    authorization_env=authorization_env,
                )
            manifest = None
            if artifact_store is not None:
                # The None case is unreachable after the validation above, but
                # keeps the type narrowing explicit for strict mypy.
                assert egress_scanner is not None
                assert egress_scanner_id is not None and egress_policy_hash is not None
                manifest = artifact_store.export_tree(
                    exchange_dir,
                    run_id=run_id,
                    scanner=egress_scanner,
                    scanner_id=egress_scanner_id,
                    policy_hash=egress_policy_hash,
                )
        except Exception as exc:
            audit.emit(
                AuditEvent(
                    type="error",
                    run_id=run_id,
                    workflow=workflow_name,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
            raise

        end_args: dict[str, object] | None = None
        if manifest is not None:
            end_args = {"artifact_manifest": manifest.to_dict()}
        audit.emit(
            AuditEvent(
                type="workflow_end",
                run_id=run_id,
                workflow=workflow_name,
                args=end_args,
                exit_status=result.exit_status,
                runtime_ms=result.runtime_ms,
            )
        )
        return result


__all__ = [
    "Runner",
    "RunnerAuthorization",
    "RunnerAuthorizationProvider",
    "RunnerController",
    "RunnerMicroVMController",
    "RunnerResult",
]
