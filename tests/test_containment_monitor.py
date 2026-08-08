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
