import json
from datetime import UTC, datetime, timedelta

import pytest

from testudo.runtime.capability import (
    CapabilityError,
    CapabilityToken,
    WorkerSupervisor,
    WorkerTerminated,
    write_token,
)

NOW = datetime(2026, 8, 8, 12, 0, tzinfo=UTC)


def make_token(*, lifetime=timedelta(minutes=10)):
    return CapabilityToken.issue(
        signing_key=b"host-secret",
        run_id="run-1",
        lease_id="lease-1",
        host_id="mac-mini",
        vm_id="vm-1",
        repository="testudo-agents",
        branch="agent/T-0254/run-1",
        base_sha="a" * 40,
        capabilities=("export",),
        allowed_paths=("agents/checkpoints/",),
        lifetime=lifetime,
        now=NOW,
    )


def test_issue_verify_and_tamper_rejection():
    token = make_token()
    verified = CapabilityToken.verify(token.to_dict(), signing_key=b"host-secret", now=NOW)
    assert verified.run_id == "run-1"
    tampered = token.to_dict()
    tampered["capabilities"] = ["export", "host-shell"]
    with pytest.raises(CapabilityError, match="signature mismatch"):
        CapabilityToken.verify(tampered, signing_key=b"host-secret", now=NOW)


def test_expired_token_is_rejected():
    token = make_token(lifetime=timedelta(seconds=1))
    with pytest.raises(CapabilityError, match="expired"):
        CapabilityToken.verify(
            token.to_dict(), signing_key=b"host-secret", now=NOW + timedelta(seconds=1)
        )


def test_supervisor_expiry_revokes_kills_and_wipes_once():
    calls: list[str] = []
    token = make_token(lifetime=timedelta(seconds=1))
    supervisor = WorkerSupervisor(
        token,
        signing_key=b"host-secret",
        kill_vm=lambda: calls.append("kill"),
        wipe_vm=lambda: calls.append("wipe"),
        revoke_token=lambda _: calls.append("revoke"),
        now=lambda: NOW + timedelta(seconds=1),
    )
    with pytest.raises(WorkerTerminated):
        supervisor.check_expiry()
    with pytest.raises(WorkerTerminated):
        supervisor.check_expiry()
    assert calls == ["revoke", "kill", "wipe"]
    assert supervisor.tripped


def test_destructive_host_operation_trips_boundary():
    calls: list[str] = []
    supervisor = WorkerSupervisor(
        make_token(),
        signing_key=b"host-secret",
        kill_vm=lambda: calls.append("kill"),
        wipe_vm=lambda: calls.append("wipe"),
        revoke_token=lambda _: calls.append("revoke"),
        now=lambda: NOW,
    )
    with pytest.raises(WorkerTerminated, match="host-boundary"):
        supervisor.request("export", target="host", destructive=True)
    assert calls == ["revoke", "kill", "wipe"]


def test_ungranted_non_destructive_capability_is_denied_without_wipe():
    calls: list[str] = []
    supervisor = WorkerSupervisor(
        make_token(),
        signing_key=b"host-secret",
        kill_vm=lambda: calls.append("kill"),
        wipe_vm=lambda: calls.append("wipe"),
        revoke_token=lambda _: calls.append("revoke"),
        now=lambda: NOW,
    )
    with pytest.raises(CapabilityError, match="not granted"):
        supervisor.request("read-host-file")
    assert calls == []


def test_write_token_is_canonical_json(tmp_path):
    path = tmp_path / "run" / "token.json"
    write_token(path, make_token())
    loaded = json.loads(path.read_text())
    assert loaded["schema"] == "contained_capability.v1"
    assert loaded["run_id"] == "run-1"
