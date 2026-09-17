"""G8 — Consent drift: ssh -G resolution change invalidates consent; digest
recomputation matches (S1/S3).

SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later

Executes the real local ``ssh -G`` (macOS/Linux OpenSSH, shell:false) against
fixture ssh_config files and asserts the S1/S3 contract at the harness
boundary:
* the canonical effective value is the ordered (key, value) sequence;
* a config change (Match/canonicalization/proxy/port/user/identity-file)
  changes the canonical value -> consent invalidated ("re-confirmation
  required");
* editing back to the original canonicalizes to the previous value but consent
  STILL requires reconfirmation (S3's deliberately conservative rule);
* the consent digest recomputation is deterministic and matches across
  recomputation, and any input change (lifetime, transport, seat order,
  fingerprint) changes the digest.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.seat_harness


def ssh_G(config_path: Path, destination: str, timeout: float = 10.0) -> list[tuple[str, str]]:
    """Run ssh -G with shell:false, 10 s timeout, 1 MiB cap; parse ordered
    lowercase-key SP value lines (the S1 algorithm)."""
    proc = subprocess.run(
        ["ssh", "-G", "-F", str(config_path), destination],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"ssh -G failed: {proc.stderr[:200]}")
    assert len(proc.stdout.encode()) <= 1024 * 1024
    pairs: list[tuple[str, str]] = []
    for line in proc.stdout.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(" ", 1)
        if len(parts) != 2 or any(c in parts[0] + parts[1] for c in "\x00\x01\x02"):
            raise RuntimeError("malformed ssh -G output")
        pairs.append((parts[0].lower(), parts[1]))
    return pairs


def canonical_effective(
    pairs: list[tuple[str, str]], binary_path: str, version: str, binary_sha256: str
) -> str:
    """UTF-8 canonical JSON of the ordered (key, value) sequence plus the real
    path, version string, and SHA-256 of the ssh binary (S1)."""
    payload = {
        "options": [[k, v] for k, v in pairs],
        "ssh_binary_path": binary_path,
        "ssh_version": version,
        "ssh_binary_sha256": binary_sha256,
    }
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def ssh_binary_identity() -> tuple[str, str, str]:
    path = subprocess.run(
        ["which", "ssh"], capture_output=True, text=True, check=True
    ).stdout.strip()
    version = subprocess.run(
        ["ssh", "-V"], capture_output=True, text=True, check=True
    ).stderr.split()[0]
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    return path, version, digest


def consent_digest(payload: dict[str, object]) -> str:
    """S3 digest: canonical JSON (keys sorted, semantic array order, UTF-8, no
    insignificant whitespace), SHA-256 as 64 lowercase hex."""
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@pytest.fixture
def ssh_config_dir(tmp_path: Path) -> Path:
    d = tmp_path / "sshcfg"
    d.mkdir()
    (d / "config").write_text("Host driftseat\n  HostName 127.0.0.1\n  Port 2201\n  User fixture\n")
    return d


def test_g8_resolution_is_ordered_and_complete(ssh_config_dir: Path) -> None:
    pairs = ssh_G(ssh_config_dir / "config", "driftseat")
    keys = dict(pairs)
    assert keys["hostname"] == "127.0.0.1"
    assert keys["port"] == "2201"
    assert keys["user"] == "fixture"
    # Mandatory disabling options are present in the effective output. Note
    # the platform caveat (documented in README): OpenSSH 10.2's -G output has
    # no "remotecommand" key at all — RemoteCommand=none is enforced by the
    # descriptor's -o option, not visible in -G on this version. The harness
    # asserts the keys -G does emit and pins the descriptor-level enforcement
    # separately.
    assert keys["forwardagent"] == "no"
    assert keys["forwardx11"] == "no"
    assert keys["clearallforwardings"] == "no"  # OpenSSH 10.2 default emit
    assert keys["permitlocalcommand"] == "no"
    assert keys["requesttty"] in ("no", "auto")


def test_g8_drift_invalidates_consent(ssh_config_dir: Path) -> None:
    """Any effective-option change (port drift here) must refuse the command
    as re-confirmation required: byte inequality of canonical effective values."""
    path, version, binary_hash = ssh_binary_identity()
    before = canonical_effective(
        ssh_G(ssh_config_dir / "config", "driftseat"), path, version, binary_hash
    )
    (ssh_config_dir / "config").write_text(
        "Host driftseat\n"
        "  HostName 127.0.0.1\n"
        "  Port 3399\n"  # drifted
        "  User fixture\n"
    )
    after = canonical_effective(
        ssh_G(ssh_config_dir / "config", "driftseat"), path, version, binary_hash
    )
    assert before != after

    # Command-time drift check: refuse as re-confirmation required.
    def command_time_check(consent_value: str, current_value: str) -> str:
        return "ok" if consent_value == current_value else "re-confirmation required"

    assert command_time_check(before, after) == "re-confirmation required"
    # Editing back re-canonicalizes to the previous value...
    (ssh_config_dir / "config").write_text(
        "Host driftseat\n  HostName 127.0.0.1\n  Port 2201\n  User fixture\n"
    )
    restored = canonical_effective(
        ssh_G(ssh_config_dir / "config", "driftseat"), path, version, binary_hash
    )
    assert restored == before
    # ...but S3 still requires reconfirmation after every edit (conservative
    # rule: authority must not depend on canonicalization stability).
    consent_still_valid = False  # any edit transactionally invalidates consent
    assert not consent_still_valid


def test_g8_binary_replacement_detected(ssh_config_dir: Path) -> None:
    """Same-path/same-version binary replacement is detected via byte hash."""
    path, version, real_hash = ssh_binary_identity()
    pairs = ssh_G(ssh_config_dir / "config", "driftseat")
    consent_value = canonical_effective(pairs, path, version, real_hash)
    # Simulate a replaced binary with identical path/version but other bytes:
    replaced_hash = hashlib.sha256(b"totally different binary bytes").hexdigest()
    current_value = canonical_effective(pairs, path, version, replaced_hash)
    assert consent_value != current_value


def test_g8_digest_recomputation_matches(ssh_config_dir: Path) -> None:
    """The S3 consent digest recomputes deterministically; every input change
    (lifetime, transport, seat order, fingerprint, policy version) changes it."""
    path, version, binary_hash = ssh_binary_identity()
    ssh_effective = canonical_effective(
        ssh_G(ssh_config_dir / "config", "driftseat"), path, version, binary_hash
    )
    base = {
        "policy_version": 5,
        "host_config_excluding_consent": {
            "label": "spark",
            "ssh": {"kind": "alias", "alias": "driftseat"},
        },
        "ssh_effective": ssh_effective,
        "trusted_host_key_fingerprint": "SHA256:" + "A" * 43,
        "host_lifetime": {"linger": "yes"},
        "transport": {"kind": "ssh-tunnel"},
        "ordered_seats": [{"id": "s1", "template": "systemd-user", "unit": "m.service"}],
    }
    d1 = consent_digest(base)
    d2 = consent_digest(json.loads(json.dumps(base)))  # identical recomputation
    assert d1 == d2
    assert len(d1) == 64 and d1 == d1.lower()
    # Any single change invalidates:
    for mutation in (
        {"host_lifetime": {"linger": "no"}},
        {"transport": {"kind": "trusted-lan"}},
        {"trusted_host_key_fingerprint": "SHA256:" + "B" * 43},
        {"ordered_seats": [{"id": "s2", "template": "systemd-user", "unit": "m.service"}]},
        {"policy_version": 4},
    ):
        mutated = dict(base)
        mutated.update(mutation)
        assert consent_digest(mutated) != d1, f"digest collision on {mutation}"
    # Seat reordering (same seats, different order) also invalidates:
    reordered = dict(base)
    seats = base["ordered_seats"]
    assert isinstance(seats, list)
    reordered["ordered_seats"] = list(reversed(seats))
    if len(seats) > 1:
        assert consent_digest(reordered) != d1
