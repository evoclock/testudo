from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from testudo.runtime.capability import CapabilityToken, WorkerTerminated
from testudo.runtime.docker import RunResult
from testudo.runtime.firecracker_adapter import FirecrackerAdapter, FirecrackerAdapterError
from testudo.runtime.isolation import IsolationProfile
from testudo.runtime.transport import Frame

KEY = b"adapter-test-secret"
NOW = datetime(2026, 8, 8, 12, 0, tzinfo=UTC)
IMAGE = "sha256:" + "b" * 64
ARTIFACT = "a" * 64


class Lifecycle:
    def __init__(self, token_id: str, *, expire: bool = False) -> None:
        self.supervisor = SimpleNamespace(token=SimpleNamespace(token_id=token_id))
        self.expire = expire
        self.closed = False
        self.stops: list[str] = []

    def check(self) -> None:
        if self.expire:
            raise WorkerTerminated("expired")

    def wait(self, *, timeout: float | None = None) -> int:
        del timeout
        self.closed = True
        return 0

    def stop(self, reason: str = "operator_stop") -> None:
        self.stops.append(reason)
        self.closed = True


class Broker:
    def __init__(self, run_id: str, token_id: str, nonce: str) -> None:
        self.run_id, self.token_id, self.nonce = run_id, token_id, nonce
        self.state = "new"
        self.closed = 0
        self.contract: dict[str, object] | None = None
        self.workflow: dict[str, object] | None = None
        self.inputs: dict[str, object] | None = None
        result = {"exit_status": 0}
        result_hash = hashlib.sha256(
            json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.frames = [
            Frame(0, run_id, token_id, nonce, "stdout", {"chunk": "hello"}),
            Frame(
                1,
                run_id,
                token_id,
                nonce,
                "receipt",
                {
                    "schema": "testudo.guest.receipt.v1",
                    "run_id": run_id,
                    "token_id": token_id,
                    "nonce": nonce,
                    "result_sha256": result_hash,
                    "artifact_digest": ARTIFACT,
                },
            ),
            Frame(2, run_id, token_id, nonce, "result", {**result, "result_sha256": result_hash}),
        ]

    def bootstrap(self, contract: dict[str, object]) -> Frame:
        self.contract = dict(contract)
        containment = contract.get("containment")
        if isinstance(containment, dict):
            self.frames[1].payload["containment"] = {**containment, "monitor_active": True}
        self.state = "ready"
        return Frame(0, self.run_id, self.token_id, self.nonce, "ready", {})

    def run(self, workflow: dict[str, object], inputs: dict[str, object]) -> None:
        self.workflow, self.inputs = dict(workflow), dict(inputs)
        self.state = "running"

    def receive(self) -> Frame:
        return self.frames.pop(0)

    def stop(self, reason: str = "operator_stop") -> None:
        del reason
        self.state = "stop_requested"

    def close(self) -> None:
        self.closed += 1


def files(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    binary, kernel, rootfs = (tmp_path / n for n in ("firecracker", "vmlinux", "rootfs.ext4"))
    binary.write_bytes(b"binary")
    kernel.write_bytes(b"kernel")
    rootfs.write_bytes(b"rootfs")
    binary.chmod(0o755)
    workflow = tmp_path / "workflow.json"
    workflow.write_text(json.dumps({"name": "demo", "steps": []}))
    return binary, kernel, rootfs, workflow


def profile(kernel: Path, rootfs: Path) -> IsolationProfile:
    return IsolationProfile(
        primitive="microvm",
        image="testudo@" + IMAGE,
        kernel_image=str(kernel),
        rootfs=str(rootfs),
        rootfs_format="ext4",
        vsock_socket="guest-vsock.sock",
        guest_cid=3,
        guest_port=10000,
    )


def token() -> CapabilityToken:
    return CapabilityToken.issue(
        signing_key=KEY,
        run_id="run-1",
        lease_id="lease-1",
        host_id="linux-backend",
        vm_id="vm-1",
        repository="testudo",
        branch="agent/T-0254/run-1",
        base_sha="c" * 40,
        capabilities=("export",),
        lifetime=timedelta(minutes=10),
        now=NOW,
    )


def setup(
    tmp_path: Path, launcher: Any, opener: Any
) -> tuple[FirecrackerAdapter, dict[str, object]]:
    binary, kernel, rootfs, workflow = files(tmp_path)
    issued = token()
    token_path = tmp_path / "token.json"
    token_path.write_text(json.dumps(issued.to_dict()))
    lease_path = tmp_path / "lease.json"
    lease_path.write_text(json.dumps({"lease_id": issued.lease_id}))
    attestation = tmp_path / "attestation.json"
    attestation.write_text("{}")
    adapter = FirecrackerAdapter(
        binary,
        runs_root=tmp_path / "runs",
        host_id="linux-backend",
        repository="testudo",
        signing_key=KEY,
        revoke_token=lambda token_id: revoked.append(token_id),
        wipe_vm=lambda: wiped.append("wipe"),
        artifact_digest=ARTIFACT,
        worker_launcher=launcher,
        broker_opener=opener,
        now=lambda: NOW,
    )
    return adapter, {
        "run_id": "run-1",
        "workflow_path": workflow,
        "workflow_name": "demo",
        "runs_dir": tmp_path / "runs" / "run-1" / "exchange",
        "isolation": profile(kernel, rootfs),
        "inputs_dir": None,
        "timeout": 5.0,
        "lease_path": lease_path,
        "lease_id": "lease-1",
        "attestation_path": attestation,
        "capability_token_path": token_path,
        "authorization_env": {"CANTUS_TASK_HASH": "task"},
        "image_digest": IMAGE,
        "event_sink": lambda _event: None,
    }


revoked: list[str] = []
wiped: list[str] = []


def test_success_binds_identity_and_forwards_maps(tmp_path: Path) -> None:
    revoked.clear()
    wiped.clear()
    lifecycle: Lifecycle | None = None
    broker: Broker | None = None

    def launch(config: Any, admitted: CapabilityToken, **kwargs: object) -> Lifecycle:
        nonlocal lifecycle
        assert config.api_socket.parent.name == "run-1"
        assert config.api_socket != config.vsock_socket
        assert kwargs["expected_identity"] == {
            name: getattr(admitted, name)
            for name in (
                "run_id",
                "lease_id",
                "host_id",
                "vm_id",
                "repository",
                "branch",
                "base_sha",
            )
        }
        lifecycle = Lifecycle(admitted.token_id)
        return lifecycle

    def open_session(_config: Any, **kwargs: object) -> Broker:
        nonlocal broker
        broker = Broker(str(kwargs["run_id"]), str(kwargs["token_id"]), str(kwargs["nonce"]))
        return broker

    adapter, kwargs = setup(tmp_path, launch, open_session)
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "inputs.json").write_text(json.dumps({"value": "hello"}))
    kwargs["inputs_dir"] = inputs
    result = adapter.run(**kwargs)  # type: ignore[arg-type]

    assert result == RunResult(0, "hello", "", result.runtime_ms)
    assert broker is not None
    assert broker.workflow == {"name": "demo", "steps": []}
    assert broker.inputs == {"value": "hello"}
    assert broker.contract is not None
    assert broker.contract["lease_id"] == "lease-1"
    assert broker.contract["host_id"] == "linux-backend"
    assert broker.contract["vm_id"] == "vm-1"
    assert broker.contract["repository"] == "testudo"
    assert broker.contract["branch"] == "agent/T-0254/run-1"
    assert broker.contract["base_sha"] == "c" * 40
    assert broker.contract["artifact_digest"] == ARTIFACT
    assert broker.contract["network"] == "none"
    assert broker.contract["read_only"] is True
    assert broker.contract["host_mounts"] == []
    assert broker is not None and revoked == [broker.token_id]
    assert wiped == ["wipe"]
    assert lifecycle is not None and lifecycle.stops == []
    assert adapter.stop_handle is None


def test_rejects_non_microvm_profile_before_launch(tmp_path: Path) -> None:
    binary, kernel, rootfs, _workflow = files(tmp_path)
    adapter = FirecrackerAdapter(binary)
    with pytest.raises(FirecrackerAdapterError, match="primitive"):
        adapter._validate_microvm_profile(IsolationProfile())
    with pytest.raises(ValueError, match="network='none'"):
        IsolationProfile(
            primitive="microvm",
            network="bridge",
            kernel_image=str(kernel),
            rootfs=str(rootfs),
            rootfs_format="ext4",
            vsock_socket="vsock.sock",
            guest_cid=3,
            guest_port=10000,
        )


def test_missing_binary_is_rejected_before_revocation(tmp_path: Path) -> None:
    _binary, kernel, rootfs, workflow = files(tmp_path)
    revoked.clear()
    adapter = FirecrackerAdapter(
        tmp_path / "missing-firecracker",
        signing_key=KEY,
        revoke_token=revoked.append,
        wipe_vm=lambda: None,
    )
    issued = token()
    token_path = tmp_path / "token.json"
    token_path.write_text(json.dumps(issued.to_dict()))
    lease = tmp_path / "lease.json"
    lease.write_text("{}")
    attestation = tmp_path / "attestation.json"
    attestation.write_text("{}")
    kwargs = {
        "run_id": "run-1",
        "workflow_path": workflow,
        "workflow_name": "demo",
        "runs_dir": tmp_path / "runs" / "run-1" / "exchange",
        "isolation": profile(kernel, rootfs),
        "inputs_dir": None,
        "timeout": 1.0,
        "lease_path": lease,
        "lease_id": "lease-1",
        "attestation_path": attestation,
        "capability_token_path": token_path,
        "authorization_env": {},
        "image_digest": IMAGE,
        "event_sink": lambda _event: None,
    }
    with pytest.raises(FirecrackerAdapterError, match="does not exist"):
        adapter.run(**kwargs)  # type: ignore[arg-type]
    assert revoked == []


def test_broker_failure_stops_worker_and_wipes_once(tmp_path: Path) -> None:
    revoked.clear()
    wiped.clear()
    lifecycle: Lifecycle | None = None

    def launch(_config: Any, admitted: CapabilityToken, **_kwargs: object) -> Lifecycle:
        nonlocal lifecycle
        lifecycle = Lifecycle(admitted.token_id)
        return lifecycle

    def fail_open(_config: Any, **_kwargs: object) -> Broker:
        raise RuntimeError("vsock unavailable")

    adapter, kwargs = setup(tmp_path, launch, fail_open)
    with pytest.raises(RuntimeError, match="vsock unavailable"):
        adapter.run(**kwargs)  # type: ignore[arg-type]
    assert lifecycle is not None and lifecycle.stops == ["broker_open_failure"]
    assert revoked == [lifecycle.supervisor.token.token_id]
    assert wiped == ["wipe"]


def test_worker_expiry_is_stopped_and_revoked(tmp_path: Path) -> None:
    revoked.clear()
    wiped.clear()
    lifecycle: Lifecycle | None = None

    def launch(_config: Any, admitted: CapabilityToken, **_kwargs: object) -> Lifecycle:
        nonlocal lifecycle
        lifecycle = Lifecycle(admitted.token_id, expire=True)
        return lifecycle

    def open_session(_config: Any, **kwargs: object) -> Broker:
        return Broker(str(kwargs["run_id"]), str(kwargs["token_id"]), str(kwargs["nonce"]))

    adapter, kwargs = setup(tmp_path, launch, open_session)
    with pytest.raises(WorkerTerminated):
        adapter.run(**kwargs)  # type: ignore[arg-type]
    assert lifecycle is not None and lifecycle.stops == ["controller_failure"]
    assert revoked == [lifecycle.supervisor.token.token_id]
    assert wiped == ["wipe"]


def test_run_can_be_reused_after_success(tmp_path: Path) -> None:
    revoked.clear()
    wiped.clear()

    def launch(_config: Any, admitted: CapabilityToken, **_kwargs: object) -> Lifecycle:
        return Lifecycle(admitted.token_id)

    def open_session(_config: Any, **kwargs: object) -> Broker:
        return Broker(str(kwargs["run_id"]), str(kwargs["token_id"]), str(kwargs["nonce"]))

    adapter, kwargs = setup(tmp_path, launch, open_session)
    assert adapter.run(**kwargs) == adapter.run(**kwargs)  # type: ignore[arg-type]


def test_paths_are_local_to_run_directory(tmp_path: Path) -> None:
    binary, _kernel, _rootfs, _workflow = files(tmp_path)
    adapter = FirecrackerAdapter(binary, runs_root=tmp_path / "runs")
    paths = adapter._prepare_paths(tmp_path / "runs" / "run-1" / "exchange")
    assert paths.api_socket.parent == paths.run_dir
    assert paths.vsock_socket.parent == paths.run_dir
    assert paths.exchange_dir.name == "exchange"
