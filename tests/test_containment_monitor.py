# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MONITOR = ROOT / "guest" / "testudo_containment_monitor.sh"
TAXONOMY = ROOT / "src" / "testudo" / "runtime" / "guest_containment_taxonomy.v1.json"


def run_monitor(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(MONITOR), *args],
        text=True,
        capture_output=True,
        check=False,
        timeout=5,
        env={"PATH": "/usr/bin:/bin"},
    )


def test_monitor_owns_canonical_taxonomy_byte_for_byte() -> None:
    embedded = run_monitor("taxonomy")
    assert embedded.returncode == 0
    expected = TAXONOMY.read_bytes()
    assert embedded.stdout.encode() == expected
    digest = hashlib.sha256(expected).hexdigest()
    assert run_monitor("taxonomy-sha256").stdout.strip() == digest
    taxonomy = json.loads(expected)
    assert taxonomy["schema"] == "guest-containment-taxonomy.v1"
    assert len(taxonomy["rules"]) == 19


def test_monitor_trips_critical_rule_and_freezes_log(tmp_path: Path) -> None:
    state = tmp_path / "session"
    first = run_monitor("decide", str(state), "GC-CRED-001", "/root/.ssh/id_ed25519")
    assert first.returncode == 0
    assert json.loads(first.stdout)["tripped"] is True
    assert (state / "kill").is_file()
    before = (state / "containment.log.jsonl").read_bytes()

    frozen = run_monitor("decide", str(state), "GC-PKG-001", "npm install x")
    assert json.loads(frozen.stdout)["frozen"] is True
    assert (state / "containment.log.jsonl").read_bytes() == before


def test_monitor_denies_network_and_shared_channel_without_fallback(tmp_path: Path) -> None:
    network = run_monitor("shim", str(tmp_path / "network"), "curl", "https://example.invalid")
    assert json.loads(network.stdout)["rule"] == "GC-NET-002"
    assert (tmp_path / "network" / "kill").is_file()

    shared = run_monitor("fs-detect", str(tmp_path / "shared"), "/tmp/agent-channel/messages")
    assert json.loads(shared.stdout)["rule"] == "GC-SHR-002"
    assert (tmp_path / "shared" / "kill").is_file()


def test_monitor_fails_closed_for_unknown_operation() -> None:
    result = run_monitor("docker-fallback")
    assert result.returncode == 2
    assert "unsupported" in result.stderr


def test_monitor_busybox_classify_is_posix_sh_portable(tmp_path: Path) -> None:
    # The monitor runs under /bin/sh in the guest; the busybox applet rewrite
    # must not rely on bash-only "${@:2}" expansion (dash: Bad substitution).
    result = run_monitor("shim", str(tmp_path / "busybox"), "busybox", "wget", "http://x")
    assert json.loads(result.stdout)["rule"] == "GC-NET-002"
    assert (tmp_path / "busybox" / "kill").is_file()


def test_monitor_liveness_evidence_names_the_dead_loop(tmp_path: Path) -> None:
    state = tmp_path / "session"
    first = run_monitor("liveness", str(state), "1 0 1")
    assert json.loads(first.stdout)["decision"] == "deny"
    assert json.loads(first.stdout)["deadLoop"] == "middle-loop"
    log = (state / "containment.log.jsonl").read_text(encoding="utf-8")
    assert "monitor loop dead: middle-loop (flags=1 0 1)" in log
    assert (state / "kill").is_file()

    healthy = run_monitor("liveness", str(tmp_path / "healthy"), "1 1 1")
    assert json.loads(healthy.stdout) == {"decision": "allow"}


def test_monitor_sweep_detects_writes_outside_the_policy_allowed_session(tmp_path: Path) -> None:
    # M3: the sweep exempts only the policy-allowed /tmp/session tree (and the
    # supervisor's own containment state). A write anywhere else in /tmp is
    # outside-session evidence and must be classified and denied.
    outside = run_monitor("fs-detect", str(tmp_path / "sweep"), "/tmp/evil/payload.bin")
    assert json.loads(outside.stdout)["decision"] == "deny"
    assert json.loads(outside.stdout)["rule"] == "GC-FSW-001"
    # ELEVATED accumulates; five outside-session denials trip the killswitch.
    for index in range(4):
        run_monitor("fs-detect", str(tmp_path / "sweep"), f"/tmp/evil/payload-{index}.bin")
    assert (tmp_path / "sweep" / "kill").is_file()

    # The sanctioned session scratch itself is allowed, with or without a
    # declared workspace, and a nested session path is exempt too.
    allowed = run_monitor("fs-detect", str(tmp_path / "sweep-allowed"), "/tmp/session/scratch.txt")
    assert json.loads(allowed.stdout) == {
        "decision": "allow",
        "path": "/tmp/session/scratch.txt",
    }

    # A declared workspace tree is also exempt; anything else is not.
    env = {"PATH": "/usr/bin:/bin", "TESTUDO_GUEST_WRITABLE_PATHS": "/runs/job /tmp/session"}
    workspace = subprocess.run(
        [str(MONITOR), "fs-detect", str(tmp_path / "sweep-workspace"), "/runs/job/out.txt"],
        text=True,
        capture_output=True,
        check=False,
        timeout=5,
        env=env,
    )
    assert json.loads(workspace.stdout) == {"decision": "allow", "path": "/runs/job/out.txt"}
    # A sibling prefix is NOT inside the allowlist: /tmp/session-evil is not
    # /tmp/session.
    sibling = subprocess.run(
        [str(MONITOR), "fs-detect", str(tmp_path / "sweep-sibling"), "/tmp/session-evil/x"],
        text=True,
        capture_output=True,
        check=False,
        timeout=5,
        env=env,
    )
    assert json.loads(sibling.stdout)["decision"] == "deny"


def test_monitor_canonicalizes_writable_paths_and_rejects_traversal(tmp_path: Path) -> None:
    # L8: writable-path prefix comparison runs on canonicalized paths. A
    # traversal spelling of a writable path is never inside the allowlist.
    env = {"PATH": "/usr/bin:/bin", "TESTUDO_GUEST_WRITABLE_PATHS": "/runs/job /tmp/session"}

    def detect(state: str, path: str) -> dict[str, object]:
        result = subprocess.run(
            [str(MONITOR), "fs-detect", str(tmp_path / state), path],
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
            env=env,
        )
        return json.loads(result.stdout)  # type: ignore[no-any-return]

    # Traversal forms are denied even though they lexically contain the
    # writable prefix.
    assert detect("traversal", "/tmp/session/../evil/file")["decision"] == "deny"
    assert detect("traversal", "/runs/job/../escape/x")["decision"] == "deny"
    assert detect("traversal", "/tmp/../etc/passwd")["decision"] == "deny"
    # Double slashes and trailing slashes canonicalize to the sanctioned form.
    assert detect("normalize", "/tmp//session/ok.txt")["decision"] == "allow"
    assert detect("normalize", "/tmp/session/./ok.txt")["decision"] == "allow"
    assert detect("normalize", "/tmp/session/")["decision"] == "allow"
    # The declared roots themselves are canonicalized: a root declared with a
    # redundant traversal still protects its canonical form, and the canonical
    # root comparison cannot be widened past the declared tree.
    assert detect("normalize", "/runs/job/file.txt")["decision"] == "allow"
    assert detect("normalize", "/runs/jobx/file.txt")["decision"] == "deny"


def test_monitor_shim_scratch_carveout_uses_canonical_root(tmp_path: Path) -> None:
    # The shim's job-scratch carve-out neutralizes scratch-local paths for the
    # cross-agent-channel and transcript heuristics only; a traversal spelling
    # outside the scratch is never neutralized.
    env = {"PATH": "/usr/bin:/bin", "TESTUDO_GUEST_WORKSPACE": "/runs/job"}

    def shim(state: str, *args: str) -> dict[str, object]:
        result = subprocess.run(
            [str(MONITOR), "shim", str(tmp_path / state), *args],
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
            env=env,
        )
        return json.loads(result.stdout)  # type: ignore[no-any-return]

    # A scratch-local coordination-looking path is neutralized (allowlist
    # path, not a GC-SHR-002 deny).
    scratch = shim("carveout", "touch", "/runs/job/task-queue/x")
    assert scratch.get("rule") != "GC-SHR-002"
    assert scratch["decision"] == "allow"
    # The same coordination path outside the scratch is denied.
    outside = shim("carveout", "touch", "/var/task-queue/x")
    assert outside["rule"] == "GC-SHR-002"
    # A traversal spelling that escapes the scratch is not neutralized.
    escape = shim("carveout", "touch", "/runs/job/../task-queue/x")
    assert escape["rule"] == "GC-SHR-002"


# Captured gate row shape (live Firecracker image): the fields are the real
# /proc/net/tcp columns, so the watcher's awk selection ($2 !~ /:0000$/) and
# the identity extraction ($2:$3:$10) are validated against reality.
# sl local_address rem_address st tx_queue:rx_queue tr tm->when retrnsmt uid timeout inode ...
NET_HEADER = (
    "  sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt"
    "   uid timeout inode\n"
)
SSHD_ROW = (
    "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000"
    " 00000000     0        0 923 1 ffff888004253480 100 0 0 10 0\n"
)
WORKLOAD_ROW = (
    "   1: 00000000:9C68 0100007F:0050 01 00000000:00000000 00:00000000"
    " 00000000  1000        0 4242 1 ffff8880042534c0 100 0 0 10 0\n"
)
# Same tuple as SSHD_ROW (0.0.0.0:22), new kernel inode: a reopened socket.
REOPENED_ROW = (
    "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000"
    " 00000000     0        0 977 1 ffff888004253500 100 0 0 10 0\n"
)


def write_table(path: Path, *rows: str) -> Path:
    path.write_text(NET_HEADER + "".join(rows), encoding="utf-8")
    return path


def baseline_of(*rows: str) -> str:
    # Same identity extraction the supervisor and the sweep use.
    identities = []
    for row in rows:
        fields = row.split()
        identities.append(f"{fields[1]}:{fields[2]}:{fields[9]}")
    return "\n".join(sorted(set(identities)))


def test_monitor_net_sweep_skips_baseline_and_flags_novel_sockets(tmp_path: Path) -> None:
    # Baseline-then-flag (live Firecracker gate defect): the guest image's own
    # sshd listener (0.0.0.0:22) must not trip GC-NET-001; workload sockets
    # created after arming must. The sweep filters against the in-memory
    # baseline identity set BEFORE gc_net_detect; net-detect is unchanged.
    state = tmp_path / "session"
    table = write_table(tmp_path / "tcp", SSHD_ROW, WORKLOAD_ROW)

    result = run_monitor(
        "net-sweep", str(state), baseline_of(SSHD_ROW), str(table)
    )
    assert result.returncode == 0
    log = (state / "containment.log.jsonl").read_text(encoding="utf-8")
    # The baseline sshd identity (0.0.0.0:22:923) is skipped entirely.
    assert "00000000:0016:00000000:0000:923" not in log
    # The novel workload identity is flagged.
    assert "00000000:9C68:0100007F:0050:4242" in log
    assert '"class":"GC-NET"' in log


def test_monitor_net_sweep_flags_reopened_socket_with_new_inode(tmp_path: Path) -> None:
    # A socket that closes and reopens after arming has a new kernel inode, so
    # its identity (local:remote:inode) differs from the baseline identity even
    # for the identical local:remote tuple. Same tuple re-listed with a
    # different inode is a NEW socket and must be flagged (correct: it is
    # workload activity, not the pre-arming listener).
    state = tmp_path / "session"
    table = write_table(tmp_path / "tcp", REOPENED_ROW)

    result = run_monitor("net-sweep", str(state), baseline_of(SSHD_ROW), str(table))
    assert result.returncode == 0
    log = (state / "containment.log.jsonl").read_text(encoding="utf-8")
    assert "00000000:0016:00000000:0000:977" in log
    assert '"class":"GC-NET"' in log


def test_monitor_net_sweep_survives_row_churn_on_a_persistent_listener(tmp_path: Path) -> None:
    # R2 regression: the sl slot renumbers and tx/rx queue + tr/tm->when fields
    # change on traffic. A persistent pre-arming listener whose row churns must
    # still be skipped — membership is keyed on local:remote:inode, not the
    # full row (full-row matching recreated the false-kill bug on churn).
    state = tmp_path / "session"
    churned = SSHD_ROW.replace("   0:", "  17:").replace(
        "00000000:00000000 00:00000000", "00001234:00005678 02:00000000"
    )
    assert churned != SSHD_ROW
    table = write_table(tmp_path / "tcp", churned)

    result = run_monitor("net-sweep", str(state), baseline_of(SSHD_ROW), str(table))
    assert result.returncode == 0
    # The churned listener is skipped: no GC-NET event, no log, no kill.
    assert not (state / "containment.log.jsonl").exists()
    assert not (state / "kill").exists()


def test_monitor_net_sweep_fails_closed_without_baseline(tmp_path: Path) -> None:
    # Fail closed: an empty baseline string flags every socket.
    state = tmp_path / "session"
    table = write_table(tmp_path / "tcp", SSHD_ROW)

    result = run_monitor("net-sweep", str(state), "", str(table))
    assert result.returncode == 0
    assert (state / "kill").is_file()


def test_contained_guest_net_baseline_end_to_end(tmp_path: Path) -> None:
    # N2: executable supervisor-level probe. Run the supervisor's actual
    # snapshot pipeline (sourced with overridden /proc paths) against a fake
    # table dir, then prove baseline-vs-novel behavior end-to-end: the
    # pre-arming listener identity is snapshotted, a novel socket is flagged,
    # and the baseline is held in a variable, not an agent-writable file.
    proc = tmp_path / "proc"
    proc.mkdir()
    # Pre-arming: only the image's own sshd listener is present. Post-arming
    # tables are prepared as files (churned listener row, then + novel socket)
    # and swapped in by the probe with cp, so no shell quoting can mangle the
    # /proc row bytes.
    write_table(proc / "tcp", SSHD_ROW)
    churned = SSHD_ROW.replace("   0:", "  17:").replace(
        "00000000:00000000 00:00000000", "00001234:00005678 02:00000000"
    )
    write_table(proc / "tcp.pre", churned)
    write_table(proc / "tcp.post", churned, WORKLOAD_ROW)
    for name in ("tcp6", "udp", "udp6"):
        (proc / name).write_text(NET_HEADER, encoding="utf-8")

    supervisor = (ROOT / "guest" / "testudo_contained_guest.sh").read_text(
        encoding="utf-8"
    )
    # Extract the exact snapshot pipeline the supervisor runs before arming.
    start = supervisor.index("NET_BASELINE=$(for table in")
    end = supervisor.index("done | sort | uniq)", start) + len("done | sort | uniq)")
    pipeline = supervisor[start:end].replace("/proc/net/", f"{proc}/")

    state = tmp_path / "state"
    monitor = ROOT / "guest" / "testudo_containment_monitor.sh"
    tcp_pre = proc / "tcp.pre"
    tcp_post = proc / "tcp.post"
    tcp = proc / "tcp"
    tcp6 = proc / "tcp6"
    udp = proc / "udp"
    udp6 = proc / "udp6"
    kill_flag = state / "kill"
    probe = tmp_path / "probe.sh"
    probe.write_text(
        "#!/bin/sh\n"
        f". '{monitor}'\n"
        f"{pipeline}\n"
        # The snapshot must produce a non-empty in-memory baseline containing
        # the pre-arming listener identity.
        'if [ -z "$NET_BASELINE" ]; then echo "no baseline" >&2; exit 3; fi\n'
        'case "$NET_BASELINE" in *00000000:0016:00000000:0000:923*) ;; *) exit 4 ;; esac\n'
        f"mkdir -p '{state}'\n"
        # Phase 1: the churned listener row must be SKIPPED (identity match,
        # not full-row match) - no kill, no log.
        f"cp '{tcp_pre}' '{tcp}'\n"
        f"gc_net_sweep '{state}' \"$NET_BASELINE\" '{tcp}' '{tcp6}'"
        f" '{udp}' '{udp6}'\n"
        f"if [ -f '{kill_flag}' ]; then echo 'churned listener flagged' >&2; exit 5; fi\n"
        # Phase 2: a novel workload socket must be FLAGGED (GC-NET-001, HIGH,
        # immediate trip). This is the supervisor's own sweep call path.
        f"cp '{tcp_post}' '{tcp}'\n"
        f"gc_net_sweep '{state}' \"$NET_BASELINE\" '{tcp}' '{tcp6}'"
        f" '{udp}' '{udp6}'\n"
        f"test -f '{kill_flag}'\n",
        encoding="utf-8",
    )
    probe.chmod(0o755)
    result = subprocess.run(
        ["/bin/sh", str(probe)],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
        env={"PATH": "/usr/bin:/bin"},
    )
    assert result.returncode == 0, result.stderr
    # No agent-writable baseline artifact exists anywhere in the state dir.
    assert not (state / "net-baseline").exists()
    # The trip evidence names the novel workload identity, not the listener.
    log = (state / "containment.log.jsonl").read_text(encoding="utf-8")
    assert "00000000:9C68:0100007F:0050:4242" in log
    assert "00000000:0016:00000000:0000:923" not in log


def test_contained_guest_snapshots_net_baseline_before_arming() -> None:
    # Static contract for the guest supervisor: the net baseline is snapshotted
    # with the same identity extraction as the sweep, BEFORE
    # TESTUDO_CONTAINMENT_ACTIVE is exported and before net_watch starts; the
    # baseline lives in the supervisor variable NET_BASELINE (no agent-writable
    # baseline file exists), and the sweep passes it to the monitor (whose
    # gc_net_detect is unchanged).
    script = (ROOT / "guest" / "testudo_contained_guest.sh").read_text(encoding="utf-8")
    baseline_line = script.index("NET_BASELINE=$(for table in")
    arming_line = script.index("export TESTUDO_CONTAINMENT_ACTIVE=")
    watch_line = script.index("net_watch & net_pid=$!")
    assert baseline_line < arming_line
    assert baseline_line < watch_line
    # Identity extraction, not raw rows: fields $2:$3:$10 on both sides.
    assert "awk 'NR > 1 && $2 !~ /:0000$/ {print $2\":\"$3\":\"$10}'" in script
    assert '| sort | uniq)' in script
    # In-memory baseline: no net-baseline file is written or read anywhere.
    assert 'net-baseline' not in script
    # The sweep runs through the monitor with the variable baseline; net_watch
    # no longer calls gc_net_detect directly per raw entry.
    assert 'gc_net_sweep "$state" "$NET_BASELINE"' in script
    assert 'gc_net_detect "$state" "$entry"' not in script
    # The empty-baseline case is auditable: explicit stderr line, still armed.
    assert "the net sweep will fail closed" in script


def test_contained_guest_sweep_covers_tmp_and_exempts_only_session_state(tmp_path: Path) -> None:
    # Static contract for the guest supervisor sweep: /tmp is swept, the
    # containment state root is pruned, and only /tmp/session paths are
    # exempted from detection.
    script = (ROOT / "guest" / "testudo_contained_guest.sh").read_text(encoding="utf-8")
    assert " /tmp;" in script, "the fs sweep must cover /tmp"
    assert '-path "$state"' in script, "the containment state root must be pruned"
    assert 'gc_canonical_path "$path"' in script
    assert "/tmp/session|/tmp/session/*) : ;;" in script
    # No other /tmp exemption exists: the session tree is the only carve-out.
    assert script.count("/tmp/session|/tmp/session/*) : ;;") == 1
