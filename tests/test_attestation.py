from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from testudo.runtime.attestation import issue_attestation, write_attestation


def test_attestation_is_hash_bound_and_short_lived(tmp_path: Path) -> None:
    now = datetime(2026, 8, 8, 10, 0, tzinfo=UTC)
    attestation = issue_attestation(
        lease_id="lease-1",
        run_id="run-1",
        image_digest=f"sha256:{'a' * 64}",
        output_exchange=tmp_path / "exchange",
        lifetime=timedelta(minutes=30),
        now=now,
        nonce="nonce-1234567890123456",
    )
    payload = {
        key: value for key, value in attestation.to_dict().items() if key != "attestationHash"
    }
    expected = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert attestation.runtime == "testudo"
    assert attestation.attestation_hash == expected
    assert attestation.expires_at.endswith("Z")


def test_attestation_writes_atomically(tmp_path: Path) -> None:
    attestation = issue_attestation(
        lease_id="lease-1",
        run_id="run-1",
        image_digest=f"sha256:{'a' * 64}",
        output_exchange=tmp_path / "exchange",
        lifetime=timedelta(minutes=1),
        nonce="nonce-1234567890123456",
    )
    path = tmp_path / "run" / "attestation.json"
    write_attestation(path, attestation)
    data = json.loads(path.read_text())
    assert data["leaseId"] == "lease-1"
    assert list(path.parent.glob(".*.tmp")) == []
