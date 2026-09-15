# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Deterministic tests for the explicit macOS native-container adapter."""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from testudo.runtime.isolation import IsolationProfile
from testudo.runtime.native_container import (
    GUEST_MODE,
    GUEST_PROTOCOL,
    NATIVE_SUPERVISOR_ENTRY,
    NativeContainerAdapter,
    NativeContainerDuplex,
    NativeContainerError,
    NativeContainerHandle,
    NativeContainerIdentity,
    NativeContainerSpec,
    NativeContainerTimeout,
    StdioGuestMode,
    build_native_container_argv,
    launch_native_container,
)
from testudo.runtime.policy import NetworkPolicy, StoragePolicy
from testudo.runtime.transport import Frame, encode_frame


class FakePipe:
    def __init__(self, data: bytes = b"") -> None:
        self.data = io.BytesIO(data)
        self.writes: list[bytes] = []
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        return self.data.read(size)

    def write(self, data: bytes) -> int:
        self.writes.append(data)
        return len(data)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    def fileno(self) -> int:
        raise ValueError("fake stream has no file descriptor")


class FakeProcess:
    def __init__(self, stdout: bytes = b"", stderr: bytes = b"") -> None:
        self.stdin = FakePipe()
        self.stdout = FakePipe(stdout)
        self.stderr = FakePipe(stderr)
        self.pid = 0
        self.returncode: int | None = None
        self.terminated = 0
        self.killed = 0
        self.wait_calls: list[float | None] = []
        self._timeout_once = False

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls.append(timeout)
        if self._timeout_once:
            self._timeout_once = False
            raise subprocess.TimeoutExpired("container", timeout)
        if self.returncode is None:
            self.returncode = 0
        return self.returncode

    def terminate(self) -> None:
        self.terminated += 1

    def kill(self) -> None:
        self.killed += 1
        self.returncode = -9


def _profile(**overrides: Any) -> IsolationProfile:
    return IsolationProfile(run_id_env="TESTUDO_RUN_ID", **overrides)


def _spec(root: Path, *, profile: IsolationProfile | None = None) -> NativeContainerSpec:
    selected = profile or _profile()
    return NativeContainerSpec(
        image="testudo@sha256:" + "a" * 64,
        workspace_dir=root / "workspace",
        identity=NativeContainerIdentity(
            lease_id="lease-1",
            run_id="run-1",
            artifact_digest="b" * 64,
            policy_digest=selected.policy_digest,
            token_id="token-1",
            nonce="nonce-1",
        ),
        isolation=selected,
        input_dir=root / "inputs",
        cache_dir=(root / "cache") if selected.storage_policy.cache else None,
        command=NATIVE_SUPERVISOR_ENTRY,
    )


def _make_dirs(root: Path, *, cache: bool = False) -> None:
    (root / "workspace").mkdir()
    (root / "inputs").mkdir()
    if cache:
        (root / "cache").mkdir()


def test_native_argv_is_explicit_no_network_read_only_and_mount_bounded(tmp_path: Path) -> None:
    _make_dirs(tmp_path)
    spec = _spec(tmp_path)

    argv = build_native_container_argv(spec)

    assert argv[:2] == ["container", "run"]
    assert "docker" not in argv
    assert "pull" not in argv
    assert "--rm" in argv
    assert "--interactive" in argv
    assert "--tty" not in argv
    assert "--read-only" in argv
    assert argv[argv.index("--network") + 1] == "none"
    assert "--no-dns" in argv
    assert "--publish" not in argv
    assert "--env-file" not in argv
    assert "testudo.lease_id=lease-1" in argv
    assert "testudo.run_id=run-1" in argv
    assert "testudo.artifact_digest=" + "b" * 64 in argv
    assert "testudo.policy_digest=" + spec.policy_digest in argv
    assert "TESTUDO_GUEST_MODE=stdio" in argv
    assert "TESTUDO_GUEST_PROTOCOL=testudo.vsock.frame.v1" in argv
    assert f"type=bind,source={(tmp_path / 'workspace').resolve()},target=/runs" in argv
    assert f"type=bind,source={(tmp_path / 'inputs').resolve()},target=/inputs,readonly" in argv
    assert sum(value == "--mount" for value in argv) == 2
    assert "/workflow.json" not in argv


def test_native_argv_mounts_only_declared_read_only_cache(tmp_path: Path) -> None:
    policy = StoragePolicy(
        phase="provision",
        cache="/cache/dependencies",
        cache_access="read_only",
    )
    _make_dirs(tmp_path, cache=True)
    spec = _spec(tmp_path, profile=IsolationProfile(storage_policy=policy))

    argv = build_native_container_argv(spec)

    assert (
        f"type=bind,source={(tmp_path / 'cache').resolve()},target=/cache/dependencies,readonly"
        in argv
    )
    assert sum(value == "--mount" for value in argv) == 3


def test_duplex_fd_reads_do_not_prefetch_past_frame_boundaries() -> None:
    read_fd, write_fd = os.pipe()
    stdout = os.fdopen(read_fd, "rb")
    stdin = FakePipe()
    duplex = NativeContainerDuplex(stdin, stdout, read_timeout=1.0)
    try:
        os.write(write_fd, b"HEADbody")
        assert duplex.recv(4) == b"HEAD"
        assert duplex.recv(4) == b"body"
    finally:
        duplex.close()
        os.close(write_fd)


def test_native_spec_rejects_network_writable_root_and_arbitrary_mounts(tmp_path: Path) -> None:
    _make_dirs(tmp_path)
    network_profile = _profile(
        network="bridge",
        network_policy=NetworkPolicy(
            phase="evaluation",
            purpose="declared_api",
            egress_hosts=("api.example.com",),
            egress_ports=(443,),
            methods=("GET",),
            max_bytes=1,
            max_duration_seconds=1,
        ),
    )
    with pytest.raises(NativeContainerError, match="network='none'"):
        NativeContainerSpec(
            image="image",
            workspace_dir=tmp_path / "workspace",
            identity=NativeContainerIdentity(
                "lease", "run", "b" * 64, network_profile.policy_digest
            ),
            isolation=network_profile,
            command=NATIVE_SUPERVISOR_ENTRY,
        )
    with pytest.raises(NativeContainerError, match="read_only=True"):
        NativeContainerSpec(
            image="image",
            workspace_dir=tmp_path / "workspace",
            identity=NativeContainerIdentity("lease", "run", "b" * 64, _profile().policy_digest),
            isolation=_profile(read_only=False),
            command=NATIVE_SUPERVISOR_ENTRY,
        )
    with pytest.raises(ValidationError, match="arbitrary host mounts"):
        StoragePolicy(host_mounts=("/host/secret",))


def test_stdio_guest_mode_is_explicit() -> None:
    mode = StdioGuestMode()
    assert mode.name == GUEST_MODE == "stdio"
    assert mode.protocol == GUEST_PROTOCOL
    assert mode.environment() == (
        "TESTUDO_GUEST_MODE=stdio",
        "TESTUDO_GUEST_PROTOCOL=testudo.vsock.frame.v1",
    )
    with pytest.raises(NativeContainerError, match="only the explicit stdio"):
        StdioGuestMode(name="socket")  # type: ignore[arg-type]


def test_duplex_bridges_existing_broker_framing_without_a_socket() -> None:
    identity = NativeContainerIdentity("lease", "run", "c" * 64, "d" * 64)
    ready = Frame(
        sequence=0,
        run_id=identity.run_id,
        token_id=identity.token_id,
        nonce=identity.nonce,
        kind="ready",
        payload={"protocol": GUEST_PROTOCOL},
    )
    stdin = FakePipe()
    duplex = NativeContainerDuplex(stdin, FakePipe(encode_frame(ready)))
    from testudo.runtime.broker import BrokerSession

    session = BrokerSession(
        duplex,
        run_id=identity.run_id,
        token_id=identity.token_id,
        nonce=identity.nonce,
    )
    assert session.bootstrap(identity.contract()).kind == "ready"
    session.close()
    assert stdin.writes
    assert stdin.closed


def _framed_success(spec: NativeContainerSpec) -> bytes:
    base_result: dict[str, object] = {"exit_status": 0, "steps": {}}
    result_hash = hashlib.sha256(
        json.dumps(base_result, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    frames = [
        Frame(0, spec.identity.run_id, spec.identity.token_id, spec.identity.nonce, "ready", {}),
        Frame(
            1,
            spec.identity.run_id,
            spec.identity.token_id,
            spec.identity.nonce,
            "stdout",
            {"chunk": "guest output\n"},
        ),
        Frame(
            2,
            spec.identity.run_id,
            spec.identity.token_id,
            spec.identity.nonce,
            "receipt",
            {
                "schema": "testudo.guest.receipt.v1",
                "run_id": spec.identity.run_id,
                "token_id": spec.identity.token_id,
                "nonce": spec.identity.nonce,
                "result_sha256": result_hash,
                "artifact_digest": spec.identity.artifact_digest,
                "containment": {**spec.contract()["containment"], "monitor_active": True},
            },
        ),
        Frame(
            3,
            spec.identity.run_id,
            spec.identity.token_id,
            spec.identity.nonce,
            "result",
            {**base_result, "result_sha256": result_hash},
        ),
    ]
    return b"".join(encode_frame(frame) for frame in frames)


def test_adapter_uses_injected_process_and_invokes_revocation_wipe(tmp_path: Path) -> None:
    _make_dirs(tmp_path)
    spec = _spec(tmp_path)
    process = FakeProcess(_framed_success(spec))
    calls: dict[str, Any] = {}
    events: list[tuple[str, str]] = []

    def fake_popen(argv: list[str], **kwargs: Any) -> FakeProcess:
        calls["argv"] = argv
        calls["kwargs"] = kwargs
        return process

    adapter = NativeContainerAdapter(
        popen=fake_popen,
        clock=lambda: 10.0,
        revocation_hook=lambda identity, reason: events.append(("revoke", reason)),
        wipe_hook=lambda identity, reason: events.append(("wipe", reason)),
    )
    result = adapter.execute(spec, {"name": "demo"}, {}, timeout=5.0)

    assert result.exit_status == 0
    assert result.stdout == "guest output\n"
    assert result.stderr == ""
    assert result.runtime_ms == 0
    assert events == [("revoke", "worker_exit"), ("wipe", "worker_exit")]
    assert calls["argv"][:2] == ["container", "run"]
    assert calls["kwargs"]["text"] is False
    assert calls["kwargs"]["shell"] is False
    assert calls["kwargs"]["env"] == {
        "PATH": "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin",
        "LC_ALL": "C",
    }
    assert process.stdin.writes


def test_handle_termination_escalates_from_stop_to_kill(tmp_path: Path) -> None:
    _make_dirs(tmp_path)
    spec = _spec(tmp_path)
    process = FakeProcess()
    process._timeout_once = True
    handle = NativeContainerHandle(process, spec)

    handle.terminate(timeout=0.25)

    assert process.terminated == 1
    assert process.killed == 1
    handle.cleanup()
    handle.cleanup()


def test_adapter_timeout_is_fail_closed_and_calls_cleanup_hooks(tmp_path: Path) -> None:
    _make_dirs(tmp_path)
    spec = _spec(tmp_path)
    # Only the bootstrap response is available; the fake clock expires before
    # the first guest frame is read.
    process = FakeProcess(
        _framed_success(spec).split(
            encode_frame(
                Frame(
                    1,
                    spec.identity.run_id,
                    spec.identity.token_id,
                    spec.identity.nonce,
                    "stdout",
                    {"chunk": "guest output\n"},
                )
            ),
            1,
        )[0]
    )
    events: list[str] = []
    clock_values = iter((100.0, 100.2))
    adapter = NativeContainerAdapter(
        popen=lambda _argv, **_kwargs: process,
        clock=lambda: next(clock_values),
        revocation_hook=lambda *_args: events.append("revoke"),
        wipe_hook=lambda *_args: events.append("wipe"),
    )

    with pytest.raises(NativeContainerTimeout):
        adapter.execute(spec, {}, {}, timeout=0.1)

    assert process.terminated == 1
    assert events == ["revoke", "wipe"]


def test_image_admission_failure_does_not_start_a_process(tmp_path: Path) -> None:
    _make_dirs(tmp_path)
    spec = _spec(tmp_path)
    started = False

    def fake_popen(_argv: list[str], **_kwargs: Any) -> FakeProcess:
        nonlocal started
        started = True
        return FakeProcess()

    with pytest.raises(NativeContainerError, match="not locally admitted"):
        launch_native_container(spec, popen=fake_popen, image_exists=lambda _image: False)
    assert not started


def test_execute_emits_verified_receipt_host_event(tmp_path: Path) -> None:
    _make_dirs(tmp_path)
    spec = _spec(tmp_path)
    process = FakeProcess(_framed_success(spec))
    events: list[Any] = []
    adapter = NativeContainerAdapter(popen=lambda _argv, **_kwargs: process, clock=lambda: 1.0)

    result = adapter.execute(spec, {"name": "demo"}, {}, timeout=5.0, event_sink=events.append)

    assert result.exit_status == 0
    assert events, "event sink must receive host events"
    receipt_events = [event for event in events if event.event == "receipt"]
    assert len(receipt_events) == 1
    payload = receipt_events[0].to_dict()
    details = payload["details"]
    assert details["schema"] == "testudo.host.receipt.v1"
    assert payload["run_id"] == spec.identity.run_id
    assert details["status"] == "success"
    assert details["result_sha256"]
    assert details["receipt_id"]
    assert details["guest_receipt"]["artifact_digest"] == spec.identity.artifact_digest
    containment = details["guest_receipt"]["containment"]
    assert containment["monitor_active"] is True
    assert [event.event for event in events] == [
        "supervisor",
        "transport",
        "transport",
        "transport",
        "stdout",
        "output",
        "receipt",
        "supervisor",
        "revoke",
        "wipe",
    ]
    for event in events:
        assert event.run_id == spec.identity.run_id
        assert event.token_id == spec.identity.token_id
    sequences = [event.sequence for event in events]
    assert sequences == list(range(len(events)))


def test_execute_rejects_receipt_without_containment_evidence(tmp_path: Path) -> None:
    _make_dirs(tmp_path)
    spec = _spec(tmp_path)
    base_result: dict[str, object] = {"exit_status": 0, "steps": {}}
    result_hash = hashlib.sha256(
        json.dumps(base_result, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    frames = [
        Frame(0, spec.identity.run_id, spec.identity.token_id, spec.identity.nonce, "ready", {}),
        Frame(
            1,
            spec.identity.run_id,
            spec.identity.token_id,
            spec.identity.nonce,
            "receipt",
            {
                "schema": "testudo.guest.receipt.v1",
                "run_id": spec.identity.run_id,
                "token_id": spec.identity.token_id,
                "nonce": spec.identity.nonce,
                "result_sha256": result_hash,
                "artifact_digest": spec.identity.artifact_digest,
            },
        ),
        Frame(
            2,
            spec.identity.run_id,
            spec.identity.token_id,
            spec.identity.nonce,
            "result",
            {**base_result, "result_sha256": result_hash},
        ),
    ]
    process = FakeProcess(b"".join(encode_frame(frame) for frame in frames))
    adapter = NativeContainerAdapter(popen=lambda _argv, **_kwargs: process, clock=lambda: 1.0)

    with pytest.raises(NativeContainerError, match="containment identity mismatch"):
        adapter.execute(spec, {"name": "demo"}, {}, timeout=5.0)


def test_execute_rejects_receipt_with_wrong_containment_digest(tmp_path: Path) -> None:
    _make_dirs(tmp_path)
    spec = _spec(tmp_path)
    base_result: dict[str, object] = {"exit_status": 0, "steps": {}}
    result_hash = hashlib.sha256(
        json.dumps(base_result, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    tampered = {
        "schema": "other",
        "taxonomy": "other",
        "taxonomy_sha256": "0" * 64,
        "killswitch_schema": "other",
        "deny_by_default": True,
        "monitor_active": True,
    }
    frames = [
        Frame(0, spec.identity.run_id, spec.identity.token_id, spec.identity.nonce, "ready", {}),
        Frame(
            1,
            spec.identity.run_id,
            spec.identity.token_id,
            spec.identity.nonce,
            "receipt",
            {
                "schema": "testudo.guest.receipt.v1",
                "run_id": spec.identity.run_id,
                "token_id": spec.identity.token_id,
                "nonce": spec.identity.nonce,
                "result_sha256": result_hash,
                "artifact_digest": spec.identity.artifact_digest,
                "containment": tampered,
            },
        ),
        Frame(
            2,
            spec.identity.run_id,
            spec.identity.token_id,
            spec.identity.nonce,
            "result",
            {**base_result, "result_sha256": result_hash},
        ),
    ]
    process = FakeProcess(b"".join(encode_frame(frame) for frame in frames))
    adapter = NativeContainerAdapter(popen=lambda _argv, **_kwargs: process, clock=lambda: 1.0)

    with pytest.raises(NativeContainerError, match="containment identity mismatch"):
        adapter.execute(spec, {"name": "demo"}, {}, timeout=5.0)


def test_spec_requires_in_image_guest_supervisor_entry(tmp_path: Path) -> None:
    _make_dirs(tmp_path)
    with pytest.raises(NativeContainerError, match="guest supervisor entry command"):
        NativeContainerSpec(
            image="testudo@sha256:" + "a" * 64,
            workspace_dir=tmp_path / "workspace",
            identity=NativeContainerIdentity("lease", "run", "b" * 64, _profile().policy_digest),
            isolation=_profile(),
        )
    with pytest.raises(NativeContainerError, match="guest supervisor as the entry command"):
        NativeContainerSpec(
            image="testudo@sha256:" + "a" * 64,
            workspace_dir=tmp_path / "workspace",
            identity=NativeContainerIdentity("lease", "run", "b" * 64, _profile().policy_digest),
            isolation=_profile(),
            command=("/bin/sh", "-c", "evil"),
        )


def test_argv_exports_run_id_env_for_guest_supervisor(tmp_path: Path) -> None:
    _make_dirs(tmp_path)
    spec = _spec(tmp_path)

    argv = build_native_container_argv(spec)

    assert "TESTUDO_RUN_ID=run-1" in argv
    run_id_env_positions = [i for i, value in enumerate(argv) if value == "--env"]
    assert any(argv[position + 1] == "TESTUDO_RUN_ID=run-1" for position in run_id_env_positions)
    with pytest.raises(ValueError, match="run_id_env"):
        IsolationProfile(run_id_env="TESTUDO_RUN_ID", primitive="microvm")


def test_receipt_status_tracks_nonzero_exit(tmp_path: Path) -> None:
    _make_dirs(tmp_path)
    spec = _spec(tmp_path)
    base_result: dict[str, object] = {"exit_status": 3, "steps": {}}
    result_hash = hashlib.sha256(
        json.dumps(base_result, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    frames = [
        Frame(0, spec.identity.run_id, spec.identity.token_id, spec.identity.nonce, "ready", {}),
        Frame(
            1,
            spec.identity.run_id,
            spec.identity.token_id,
            spec.identity.nonce,
            "receipt",
            {
                "schema": "testudo.guest.receipt.v1",
                "run_id": spec.identity.run_id,
                "token_id": spec.identity.token_id,
                "nonce": spec.identity.nonce,
                "result_sha256": result_hash,
                "artifact_digest": spec.identity.artifact_digest,
                "containment": {**spec.contract()["containment"], "monitor_active": True},
            },
        ),
        Frame(
            2,
            spec.identity.run_id,
            spec.identity.token_id,
            spec.identity.nonce,
            "result",
            {**base_result, "result_sha256": result_hash},
        ),
    ]
    process = FakeProcess(b"".join(encode_frame(frame) for frame in frames))
    # The fake process exits only after the guest result frame is consumed,
    # mirroring a real guest that terminates with a nonzero status.
    consumed = 0
    original_read = process.stdout.data.read
    total = len(process.stdout.data.getvalue())

    def counted_read(size: int = -1) -> bytes:
        nonlocal consumed
        value = original_read(size)
        consumed += len(value)
        return value

    process.stdout.data.read = counted_read  # type: ignore[method-assign]

    def poll_after_frames() -> int | None:
        return 3 if consumed >= total else None

    process.poll = poll_after_frames  # type: ignore[method-assign]
    process.returncode = 3
    events: list[Any] = []
    adapter = NativeContainerAdapter(popen=lambda _argv, **_kwargs: process, clock=lambda: 1.0)

    result = adapter.execute(spec, {"name": "demo"}, {}, timeout=5.0, event_sink=events.append)

    assert result.exit_status == 3
    receipt_events = [event for event in events if event.event == "receipt"]
    assert len(receipt_events) == 1
    details = receipt_events[0].to_dict()["details"]
    assert details["status"] == "failed"
    assert details["exit_status"] == 3


def test_spec_rejects_whitespace_in_declared_guest_paths(tmp_path: Path) -> None:
    """Whitespace in declared guest paths corrupts the space-separated allowlist."""
    from testudo.runtime.policy import StoragePolicy

    with pytest.raises((NativeContainerError, ValueError), match=r"whitespace|canonical"):
        NativeContainerSpec(
            image="localhost/testudo:latest@sha256:" + "a" * 64,
            workspace_dir=tmp_path,
            identity=NativeContainerIdentity(
                lease_id="lease-ws",
                run_id="run-ws",
                artifact_digest="b" * 64,
                policy_digest=hashlib.sha256(b"policy-ws").hexdigest(),
                token_id="token-ws",
                nonce="nonce-ws",
            ),
            isolation=IsolationProfile(
                storage_policy=StoragePolicy(workspace="/runs/a b"),
                run_id_env="TESTUDO_RUN_ID",
            ),
        )


def test_native_argv_exports_declared_writable_paths_to_the_guest_watcher(
    tmp_path: Path,
) -> None:
    _make_dirs(tmp_path)
    spec = _spec(tmp_path)

    argv = build_native_container_argv(spec)

    # The guest containment watcher's allowlist is bound to the declared
    # run-local storage policy: workspace writes are sanctioned, /tmp/session
    # remains the supervisor's own scratch, and nothing else is writable.
    assert "TESTUDO_GUEST_WORKSPACE=/runs" in argv
    assert "TESTUDO_GUEST_WRITABLE_PATHS=/runs /tmp/session" in argv


def test_native_argv_writable_paths_follow_declared_workspace_policy(
    tmp_path: Path,
) -> None:
    _make_dirs(tmp_path)
    policy = StoragePolicy(workspace="/runs/job")
    spec = _spec(
        tmp_path,
        profile=_profile(storage_policy=policy, workdir="/runs/job"),
    )

    argv = build_native_container_argv(spec)

    assert "TESTUDO_GUEST_WORKSPACE=/runs/job" in argv
    assert "TESTUDO_GUEST_WRITABLE_PATHS=/runs/job /tmp/session" in argv
    assert f"type=bind,source={(tmp_path / 'workspace').resolve()},target=/runs/job" in argv
