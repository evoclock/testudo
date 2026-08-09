# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Host-side runner for one isolated Testudo workflow.

The container receives only a controller-created exchange directory.  The
host-owned audit log is outside that mount.  Governed callers can provide an
:class:`~testudo.artifacts.ArtifactStore` and scanner; output is then promoted
only through the scanned egress importer after the container exits.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from datetime import timedelta
from pathlib import Path

from testudo.artifacts import ArtifactStore, ChunkScanner
from testudo.audit import AuditEvent, AuditLog
from testudo.runtime import docker
from testudo.runtime.attestation import issue_attestation, write_attestation
from testudo.runtime.backend import ExecutionBackend, coerce_backend
from testudo.runtime.isolation import IsolationProfile


class Runner:
    """Coordinate audit logging and optional scanned output promotion."""

    def __init__(
        self,
        runs_root: Path,
        *,
        backend: ExecutionBackend | str = ExecutionBackend.MICROVM,
        microvm_invoke: Callable[..., docker.RunResult] | None = None,
    ) -> None:
        self.runs_root = runs_root
        self.backend = coerce_backend(backend)
        self.microvm_invoke = microvm_invoke
        runs_root.mkdir(parents=True, exist_ok=True)

    def run(
        self,
        *,
        workflow_path: Path,
        workflow_name: str,
        isolation: IsolationProfile,
        backend: ExecutionBackend | str | None = None,
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
    ) -> docker.RunResult:
        """Execute a workflow and return its result.

        When ``artifact_store`` is supplied, ``egress_scanner`` is mandatory.
        The container can write only to ``exchange``; the audit log remains
        outside the writable mount and every output file is scanned before
        promotion into the host-local CAS.

        ``microvm`` is the governed default. Docker is an explicit compatibility
        backend for callers that opt in with ``backend="docker"``.
        """
        selected_backend = coerce_backend(backend or self.backend)
        if selected_backend is ExecutionBackend.MICROVM and self.microvm_invoke is None:
            raise RuntimeError("microVM backend selected but no host microVM adapter is configured")
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

        run_id = uuid.uuid4().hex[:12]
        run_dir = self.runs_root / run_id
        run_dir.mkdir()
        exchange_dir = run_dir / "exchange"
        exchange_dir.mkdir()
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
                    "backend": selected_backend.value,
                    "contained": contained,
                    **({"attestation_hash": attestation.attestation_hash} if attestation else {}),
                },
            )
        )

        try:
            invoker: Callable[..., docker.RunResult]
            if selected_backend is ExecutionBackend.DOCKER:
                invoker = docker.invoke
            else:
                assert self.microvm_invoke is not None
                invoker = self.microvm_invoke
            result = invoker(
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
