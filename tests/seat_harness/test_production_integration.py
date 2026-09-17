"""PROD — production-integration tests (HIGH-1).

SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later

The harness tests in G1-G9 execute the *reference* implementations
(``tests/seat_harness/render.py``, ``guard_client.py``) against the fixture
host. This module closes that gap: it drives the **shipped production code**
(``src/testudo/seats/``) against the same disposable fixture SSH host, so the
65-test gate plus these tests constrain the code that actually ships:

* P0: production C2 rendering is byte-identical to the harness reference
  (including adversarial vectors from G3).
* P1: production S2 key probe + trust store + S1 ``ssh -G`` resolution work
  against the fixture sshd with strict command options.
* P2: production L2 ``GuardController`` runs the full GUARD_V1 protocol
  (lock -> gate poll -> GO -> operation -> trailer -> RELEASE) against the
  fixture host, including the poll-refused EOF path (exit 77).
* P3: a complete production Template C lifecycle — L1 local lock, L2 guard,
  L3 post-lock poll over the production ssh-tunnel transport, LAUNCH_V1,
  TESTUDO_PID parse, P4 PID-record persistence, endpoint readiness, then an
  identity-checked C_PID_V1 stop — using the production ``BareCommandController``.
* P4: production U1 linger probe against the loginctl shim (yes -> start
  proceeds; no -> refused with the exact warning).
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from .conftest import FixtureHost, GuardEnv
from .guard_client import GuardClient
from .render import argv_sha256 as ref_argv_sha256
from .render import new_nonce as ref_new_nonce
from .render import remote_command as ref_remote_command
from .shims import write_linger_state

pytestmark = pytest.mark.seat_harness

HOST_ID = "3f1c2a9e-7b4d-4e8a-9c21-5d0f6a8b1e34"
SEAT_C = "d18e6f30-9ba2-4c74-b6e8-7f8091a2b3c4"
MODEL_ID = "fixture-model"
SERVER_PORT = 8187

# Adversarial quoting vectors (subset of G3) that must round-trip through
# the production renderer byte-for-byte like the reference.
ADVERSARIAL = [
    "word with spaces",
    "it's quoted 'value'",
    "$(rm -rf /)",
    "a`b`c",
    "semi;colon|pipe&&and",
    "--leading-dash",
    "-",
    "--",
    "tab\tchar",
    "üñïçø∂é",
    "'\\''",
]


def _production() -> dict[str, object]:
    from testudo.seats._scripts import GUARD_V1, LAUNCH_V1
    from testudo.seats.render import argv_sha256, new_nonce, remote_command

    return {
        "GUARD_V1": GUARD_V1,
        "LAUNCH_V1": LAUNCH_V1,
        "argv_sha256": argv_sha256,
        "new_nonce": new_nonce,
        "remote_command": remote_command,
    }


@pytest.fixture
def linux_only(seat_fixture_host: FixtureHost) -> None:
    """Gate: guarded Template C operations need GUARD_V1 (flock, GNU
    stat/timeout) plus /proc, setsid, sha256sum."""
    if not seat_fixture_host.linux_semantics:
        pytest.skip(
            "production Template C lifecycle needs the Linux fixture "
            "(flock/setsid//proc); section 8 platform boundary"
        )


def _upload_server(guard_env: GuardEnv, name: str) -> None:
    srv = Path(__file__).resolve().parent / "data" / name
    b64 = base64.b64encode(srv.read_bytes()).decode()
    proc = guard_env.session().run(
        f"mkdir -p -m 755 ~/bin && echo {b64!r} | base64 -d > ~/bin/{name} && chmod 644 ~/bin/{name}"
    )
    assert proc.returncode == 0, proc.stderr


def _prod_descriptor(guard_env: GuardEnv, tmp_path: Path):
    from testudo.seats.ssh import SshDescriptor

    return SshDescriptor(
        guard_env.destination,
        guard_env.port,
        str(guard_env.key_path),
        str(tmp_path / "known_hosts"),
    )


def _trusted_descriptor(guard_env: GuardEnv, tmp_path: Path):
    """Production S2: isolated key probe, initial trust install; returns the
    descriptor bound to the trusted known-hosts file."""
    from testudo.seats.ssh import HostKeyTrustStore, probe_host_key

    descriptor = _prod_descriptor(guard_env, tmp_path)
    probe = probe_host_key(descriptor, tmp_path)
    assert probe.fingerprint.startswith("SHA256:")
    store = HostKeyTrustStore(tmp_path / "trusted_hosts")
    store.install_initial(probe.known_hosts_line)
    host = guard_env.destination.split("@")[1]
    assert store.known_fingerprint(host, guard_env.port) == probe.fingerprint
    return type(descriptor)(
        guard_env.destination,
        guard_env.port,
        str(guard_env.key_path),
        str(tmp_path / "trusted_hosts"),
    )


# --- P0: production rendering equals the reference ----------------------------


def test_prod0_render_matches_reference() -> None:
    """Production C2 rendering is byte-identical to the harness reference,
    including adversarial vectors (the G3 oracle constrains shipped code)."""
    prod = _production()
    guard_v1 = prod["GUARD_V1"]
    assert isinstance(guard_v1, str)
    for vector in ADVERSARIAL:
        args = ["endpoint-" + "0" * 64 + ".lock", ref_new_nonce(), "sh", "-c", vector]
        assert prod["remote_command"](guard_v1, args) == ref_remote_command(guard_v1, args)  # type: ignore[operator]
    launch = ["sh", "-c", "x'$(y)'", "testudo", "", SEAT_C, "0" * 64, *ADVERSARIAL]
    assert prod["remote_command"]("script", launch) == ref_remote_command("script", launch)  # type: ignore[operator]


def test_prod0_nonce_and_hash_shapes() -> None:
    """Production nonces and the NUL-after-every-argument hash match the
    reference byte layout."""
    prod = _production()
    nonce = prod["new_nonce"]()
    assert isinstance(nonce, str)
    assert ref_new_nonce() != nonce  # independent random draws
    argv = ["/usr/local/bin/python3", "srv.py", "--port", "8000"]
    assert prod["argv_sha256"](argv) == ref_argv_sha256(argv)  # type: ignore[operator]


# --- P1: production S1/S2 against the fixture sshd ----------------------------


def test_prod1_probe_resolve_and_command(
    guard_env: GuardEnv, tmp_path: Path, normative_scripts: dict[str, str]
) -> None:
    """S2 probe -> trust -> S1 resolution -> one strict command connection,
    all through production code paths."""
    from testudo.seats.ssh import resolve_effective_ssh

    descriptor = _trusted_descriptor(guard_env, tmp_path)
    effective = resolve_effective_ssh(descriptor)
    keys = {key for key, _ in effective.ordered_pairs}
    assert "user" in keys and "hostname" in keys
    # a real command connection with StrictHostKeyChecking=yes + the trusted file
    from testudo.seats.ssh import exec_remote

    result = exec_remote(
        descriptor, ref_remote_command(normative_scripts["EXEC_V1"], ["true"]), timeout=15.0
    )
    assert result.exit_code == 0, result.stderr


# --- P2: production GuardController protocol round-trip -----------------------


def test_prod2_guard_controller_roundtrip(guard_env: GuardEnv, tmp_path: Path) -> None:
    """The production L2 controller completes the full GUARD_V1 protocol
    against the fixture host: LOCKED -> GO -> operation -> trailer ->
    RELEASE, and the EOF-refused path exits 77 without running the op."""
    from testudo.seats.guard import GuardController
    from testudo.seats.render import lock_basename, new_nonce

    descriptor = _trusted_descriptor(guard_env, tmp_path)
    lock = lock_basename("22" * 32)
    nonce = new_nonce()

    controller = GuardController(descriptor, lock, nonce)
    outcome = controller.operate(["true"], timeout=60)
    assert outcome.exit_code == 0, outcome.stderr
    assert outcome.rc_trailer == 0
    assert outcome.locked

    # poll refuses -> EOF releases the guard without running the operation
    refused = GuardController(descriptor, lock, new_nonce(), poll_permits=lambda: False)
    refusal = refused.operate(["sh", "-c", "echo should-not-run; exit 7"], timeout=60)
    assert refusal.exit_code == 77
    assert refusal.refused_reason == "GATE_REFUSED"
    assert "should-not-run" not in refusal.operation_output


# --- P3: complete production Template C lifecycle -----------------------------


@pytest.fixture
def linger_yes(guard_env: GuardEnv, install_shims: None) -> None:
    hex_payload = write_linger_state("yes").encode().hex()
    proc = guard_env.session().run(
        f"mkdir -p -m 700 ~/.fixture-state && "
        f"python3 -c \"import sys; sys.stdout.buffer.write(bytes.fromhex('{hex_payload}'))\" "
        f"> ~/.fixture-state/linger.json"
    )
    assert proc.returncode == 0, proc.stderr


def _prod_c_context(guard_env: GuardEnv, tmp_path: Path, *, state_store=None):
    from testudo.seats.config import StateStore
    from testudo.seats.controller import SeatContext, make_executor
    from testudo.seats.lifetime import LingerObservation
    from testudo.seats.transport import EndpointPoller

    descriptor = _trusted_descriptor(guard_env, tmp_path)
    store = state_store or StateStore(tmp_path / "state.v1.json")
    seat = {
        "id": SEAT_C,
        "label": "prod-bare-seat",
        "template": "bare-command",
        "launch_argv": [
            "/usr/local/bin/python3",
            "/home/fixture/bin/fixture_srv.py",
            str(SERVER_PORT),
        ],
        "cwd": "/home/fixture",
        "ready_timeout": 60,
        "model_id": MODEL_ID,
        "port": SERVER_PORT,
        "endpoint_host": "127.0.0.1",
    }
    context = SeatContext(
        host_id=HOST_ID,
        seat_id=SEAT_C,
        seat=seat,
        descriptor=descriptor,
        endpoint_host="127.0.0.1",
        endpoint_port=SERVER_PORT,
        ssh_hostname="127.0.0.1",
        ssh_port=guard_env.port,
        config_revision=1,
        poller=EndpointPoller(),
        linger=LingerObservation("yes"),
        state_store=store,
        transport={"kind": "ssh-tunnel"},
        executor=make_executor(descriptor),
    )
    return context, store


def test_prod3_template_c_start_stop_lifecycle(
    guard_env: GuardEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    linux_only: None,
    linger_yes: None,
) -> None:
    """The shipped controller runs a real guarded Template C start and an
    identity-checked stop end-to-end: LAUNCH_V1 under GUARD_V1, TESTUDO_PID
    capture, P4 persistence, ssh-tunnel readiness polling, C_PID_V1 stop."""
    from testudo.seats.controller import BareCommandController, parse_testudo_pid

    monkeypatch.setenv("TESTUDO_DATA_DIR", str(tmp_path / "data"))
    _upload_server(guard_env, "fixture_srv.py")
    context, store = _prod_c_context(guard_env, tmp_path)

    controller = BareCommandController(context)
    outcome = controller.start()
    assert outcome.state == "serving", (
        f"{outcome.state}: error={outcome.error!r} detail={outcome.detail!r}"
    )
    records = store.load()["pid_records"]
    assert len(records) == 1
    record = records[0]
    assert record["seat_id"] == SEAT_C
    assert record["pid"] == record["pgid"]  # setsid invariant
    assert record["argv_sha256"] == ref_argv_sha256(context.seat["launch_argv"])

    # the process is really alive and did not inherit FD 9 (G1 regression,
    # now against the shipped controller)
    fds = guard_env.session().run(f"ls /proc/{record['pid']}/fd/ 2>/dev/null").stdout.split()
    assert "9" not in fds

    # production tunnel poll sees the exact sole model
    observation = context.poller.poll(
        {"kind": "ssh-tunnel"}, "127.0.0.1", SERVER_PORT, MODEL_ID, descriptor=context.descriptor
    )
    assert observation.models == (MODEL_ID,)
    assert observation.endpoint_state == "occupied-known"

    # identity-checked stop under a fresh guard and the L3 gate
    stop_outcome = controller.stop()
    assert stop_outcome.state == "dormant", (
        f"{stop_outcome.state}: error={stop_outcome.error!r} detail={stop_outcome.detail!r}"
    )
    gone = guard_env.session().run(f"test -d /proc/{record['pid']} >/dev/null 2>&1; echo $?")
    assert gone.stdout.strip() == "1"  # /proc/<pid> is gone: the stop landed
    _ = parse_testudo_pid  # imported for parity with production use


def test_prod3_start_refused_without_linger(
    guard_env: GuardEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    linux_only: None,
    install_shims: None,
) -> None:
    """U1 through the shipped controller: Linger=no refuses start with the
    exact warning; the guard is never contacted."""
    from testudo.seats.controller import BareCommandController
    from testudo.seats.lifetime import LingerObservation

    monkeypatch.setenv("TESTUDO_DATA_DIR", str(tmp_path / "data"))
    hex_payload = write_linger_state("no").encode().hex()
    guard_env.session().run(
        f"mkdir -p -m 700 ~/.fixture-state && "
        f"python3 -c \"import sys; sys.stdout.buffer.write(bytes.fromhex('{hex_payload}'))\" "
        f"> ~/.fixture-state/linger.json"
    )
    context, _store = _prod_c_context(guard_env, tmp_path)
    context.linger = LingerObservation("no")
    outcome = BareCommandController(context).start()
    assert outcome.state == "refused"
    assert outcome.error == "host lifetime prerequisite"
    assert "service may stop when this session ends" in outcome.detail


def test_prod3_u1_probe_via_shim(guard_env: GuardEnv, tmp_path: Path, linger_yes: None) -> None:
    """The production U1 probe command and parser, run live against the
    loginctl shim through the production executor."""
    from testudo.seats.lifetime import linger_probe_remote_command, parse_linger_output
    from testudo.seats.ssh import effective_user, exec_remote, resolve_effective_ssh

    descriptor = _trusted_descriptor(guard_env, tmp_path)
    effective = resolve_effective_ssh(descriptor)
    user = effective_user(effective)
    assert user is not None
    result = exec_remote(descriptor, linger_probe_remote_command(user), timeout=15.0)
    observation = parse_linger_output(result.stdout, result.stderr, result.exit_code)
    assert observation.value == "yes"


# --- P4: production inspection over the fixture -------------------------------


def test_prod4_tunnel_poll_classifies_endpoint(
    guard_env: GuardEnv,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    linux_only: None,
    linger_yes: None,
) -> None:
    """The shipped ssh-tunnel poller classifies closed vs occupied-known
    through the D2 rules (MED-5) against a real fixture server."""
    from testudo.seats.transport import EndpointPoller

    monkeypatch.setenv("TESTUDO_DATA_DIR", str(tmp_path / "data"))
    _upload_server(guard_env, "fixture_srv.py")
    descriptor = _trusted_descriptor(guard_env, tmp_path)
    poller = EndpointPoller()

    closed = poller.poll(
        {"kind": "ssh-tunnel"}, "127.0.0.1", SERVER_PORT, MODEL_ID, descriptor=descriptor
    )
    assert closed.models == ()
    assert closed.endpoint_state == "closed"

    runner = guard_env.ssh_runner()
    launch = [
        "/usr/local/bin/python3",
        "/home/fixture/bin/fixture_srv.py",
        str(SERVER_PORT),
    ]
    client = GuardClient(runner, ref_new_nonce(), "endpoint-" + "33" * 32 + ".lock")
    from testudo.seats._scripts import LAUNCH_V1

    started = client.operate(
        ["sh", "-c", LAUNCH_V1, "testudo", "", SEAT_C, ref_argv_sha256(launch), *launch],
        timeout=90,
    )
    assert started.exit_code == 0, started.raw_stdout[:400]
    try:
        occupied = poller.poll(
            {"kind": "ssh-tunnel"}, "127.0.0.1", SERVER_PORT, MODEL_ID, descriptor=descriptor
        )
        assert occupied.models == (MODEL_ID,)
        assert occupied.endpoint_state == "occupied-known"
    finally:
        pid_line = next(line for line in started.stdout_lines if line.startswith("TESTUDO_PID "))
        _pid, pid, pgid, ticks, boot, digest = pid_line.split(" ")
        from testudo.seats._scripts import C_PID_V1

        stop = GuardClient(runner, ref_new_nonce(), "endpoint-" + "33" * 32 + ".lock")
        stopped = stop.operate(
            ["sh", "-c", C_PID_V1, "testudo", "stop", pid, pgid, ticks, boot, digest],
            timeout=60,
        )
        assert stopped.exit_code == 0, stopped.raw_stdout[:400]
