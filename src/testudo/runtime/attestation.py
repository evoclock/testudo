from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class RuntimeAttestation:
    """Short-lived host assertion mounted read-only into a contained run."""

    runtime: str
    lease_id: str
    run_id: str
    image_digest: str
    nonce: str
    issued_at: str
    expires_at: str
    output_exchange: str
    attestation_hash: str

    def to_dict(self) -> dict[str, str]:
        return {
            "runtime": self.runtime,
            "leaseId": self.lease_id,
            "runId": self.run_id,
            "imageDigest": self.image_digest,
            "nonce": self.nonce,
            "issuedAt": self.issued_at,
            "expiresAt": self.expires_at,
            "outputExchange": self.output_exchange,
            "attestationHash": self.attestation_hash,
        }


def issue_attestation(
    *,
    lease_id: str,
    run_id: str,
    image_digest: str,
    output_exchange: Path | str,
    lifetime: timedelta,
    now: datetime | None = None,
    nonce: str | None = None,
) -> RuntimeAttestation:
    """Create a hash-bound Testudo attestation; caller mounts it read-only."""
    if not lease_id or not run_id or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest):
        raise ValueError("lease_id, run_id, and immutable sha256 image_digest are required")
    issued = (now or datetime.now(UTC)).astimezone(UTC)
    expires = issued + lifetime
    payload: dict[str, str] = {
        "runtime": "testudo",
        "leaseId": lease_id,
        "runId": run_id,
        "imageDigest": image_digest,
        "nonce": nonce or secrets.token_hex(16),
        "issuedAt": issued.isoformat().replace("+00:00", "Z"),
        "expiresAt": expires.isoformat().replace("+00:00", "Z"),
        "outputExchange": str(Path(output_exchange).resolve()),
    }
    return RuntimeAttestation(
        runtime=payload["runtime"],
        lease_id=payload["leaseId"],
        run_id=payload["runId"],
        image_digest=payload["imageDigest"],
        nonce=payload["nonce"],
        issued_at=payload["issuedAt"],
        expires_at=payload["expiresAt"],
        output_exchange=payload["outputExchange"],
        attestation_hash=_digest(payload),
    )


def write_attestation(path: Path | str, attestation: RuntimeAttestation) -> None:
    """Write an attestation atomically for a read-only container mount."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            json.dump(attestation.to_dict(), handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


__all__ = ["RuntimeAttestation", "issue_attestation", "write_attestation"]
