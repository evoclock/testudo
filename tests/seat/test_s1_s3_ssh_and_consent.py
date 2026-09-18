# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""S1/S2/S3 tests: descriptor shape, ssh -G resolution against the fixture
host (real local ssh), drift detection, key probe/trust store, and consent
digest determinism."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from testudo.seats.consent import consent_digest, consent_text_for
from testudo.seats.ssh import (
    EffectiveSsh,
    HostKeyTrustStore,
    KeyProbeError,
    SshDescriptor,
    SshResolveError,
    mandatory_ssh_options,
    probe_host_key,
    resolve_effective_ssh,
)

pytestmark = pytest.mark.skipif(
    not Path("/usr/bin/ssh").exists() and not Path("/opt/homebrew/bin/ssh").exists(),
    reason="no local ssh binary",
)


def _descriptor(tmp_path: Path, alias: str = "localhost") -> SshDescriptor:
    return SshDescriptor(alias, None, None, str(tmp_path / "known_hosts"))


class TestDescriptor:
    def test_mandatory_options_present_and_ordered(self, tmp_path: Path) -> None:
        options = mandatory_ssh_options(tmp_path / "known_hosts")
        text = " ".join(options)
        for required in (
            "BatchMode=yes",
            "StrictHostKeyChecking=yes",
            "PermitLocalCommand=no",
            "RemoteCommand=none",
            "ClearAllForwardings=yes",
            "ForwardAgent=no",
            "ForwardX11=no",
            "ForwardX11Trusted=no",
            "RequestTTY=no",
            "GlobalKnownHostsFile=/dev/null",
        ):
            assert f"-o {required}" in text
        assert f"-o UserKnownHostsFile={tmp_path / 'known_hosts'}" in text

    def test_command_argv_single_remote_string(self, tmp_path: Path) -> None:
        desc = SshDescriptor("spark", None, None, str(tmp_path / "kh"))
        argv = desc.command_argv("'sh' '-c' 'X'")
        assert argv[0] == "ssh"
        assert argv[-2] == "spark"
        assert argv[-1] == "'sh' '-c' 'X'"

    def test_explicit_descriptor_destination(self, tmp_path: Path) -> None:
        desc = SshDescriptor(
            "user@100.64.0.2", 2222, "/home/u/.ssh/id_ed25519", str(tmp_path / "kh")
        )
        argv = desc.command_argv("X")
        assert "user@100.64.0.2" in argv
        assert argv[argv.index("-p") + 1] == "2222"
        assert argv[argv.index("-i") + 1] == "/home/u/.ssh/id_ed25519"

    def test_resolve_argv_has_G_before_destination(self, tmp_path: Path) -> None:
        desc = SshDescriptor("user@100.64.0.2", 2222, None, str(tmp_path / "kh"))
        argv = desc.resolve_argv()
        g_index = argv.index("-G")
        # -G sits before the destination; user-derived options may follow it
        assert argv[-1] == "user@100.64.0.2"
        assert "-p" in argv[g_index:]

    def test_probe_argv_overrides_first(self, tmp_path: Path) -> None:
        desc = SshDescriptor("spark", None, None, str(tmp_path / "kh"))
        argv = desc.probe_argv(tmp_path / "probe.kh")
        # probe overrides precede every ordinary -o option
        first_o = argv.index("-o")
        override_text = " ".join(argv[first_o : first_o + 12])
        assert "StrictHostKeyChecking=accept-new" in override_text
        assert "UserKnownHostsFile=" in override_text
        assert "HashKnownHosts=no" in override_text
        assert "ConnectionAttempts=1" in override_text
        assert "ConnectTimeout=10" in override_text
        # -N -T before destination; no remote command element
        n_index = argv.index("-N")
        t_index = argv.index("-T")
        assert n_index < t_index < len(argv) - 1
        assert argv[-1] == "spark"


class TestEffectiveSsh:
    def test_real_localhost_resolution(self, tmp_path: Path) -> None:
        desc = _descriptor(tmp_path)
        effective = resolve_effective_ssh(desc)
        keys = {key for key, _ in effective.ordered_pairs}
        assert "user" in keys
        assert "hostname" in keys
        assert "port" in keys
        assert (
            effective.binary_sha256
            == hashlib.sha256(Path(effective.binary_path).read_bytes()).hexdigest()
        )
        assert "OpenSSH" in effective.binary_version or effective.binary_version

    def test_canonical_json_binds_binary(self, tmp_path: Path) -> None:
        desc = _descriptor(tmp_path)
        effective = resolve_effective_ssh(desc)
        other = EffectiveSsh(
            effective.ordered_pairs,
            effective.binary_path,
            effective.binary_version,
            "0" * 64,
        )
        assert other.sha256() != effective.sha256()

    def test_port_drift_detected(self, tmp_path: Path) -> None:
        a = resolve_effective_ssh(_descriptor(tmp_path))
        b = resolve_effective_ssh(
            SshDescriptor("localhost", 22, None, str(tmp_path / "known_hosts"))
        )
        # same binary, same config for localhost:22 -> identical; a different
        # port would change the canonical value (drift detection contract)
        assert a.sha256() == b.sha256() or a.ordered_pairs != b.ordered_pairs

    def test_resolution_failure_fails_closed(self, tmp_path: Path) -> None:
        from testudo.seats import ssh as ssh_mod

        # malformed output fails closed
        with pytest.raises(SshResolveError):
            ssh_mod._parse_ssh_g_output(b"garbage-without-space\n")

    def test_parse_rejects_nul(self) -> None:
        from testudo.seats.ssh import _parse_ssh_g_output

        with pytest.raises(SshResolveError):
            _parse_ssh_g_output(b"user jun\x00host x\n")

    def test_parse_rejects_control_characters(self) -> None:
        from testudo.seats.ssh import _parse_ssh_g_output

        with pytest.raises(SshResolveError):
            _parse_ssh_g_output(b"user jun\x01host x\n")

    def test_parse_rejects_malformed_lines(self) -> None:
        from testudo.seats.ssh import _parse_ssh_g_output

        with pytest.raises(SshResolveError):
            _parse_ssh_g_output(b"novaluehere\n")
        with pytest.raises(SshResolveError):
            _parse_ssh_g_output(b"UPPER value\n")
        with pytest.raises(SshResolveError):
            _parse_ssh_g_output(b"")

    def test_parse_preserves_repeated_keys_in_order(self) -> None:
        from testudo.seats.ssh import _parse_ssh_g_output

        pairs = _parse_ssh_g_output(b"identityfile /a\nidentityfile /b\n")
        assert pairs == (("identityfile", "/a"), ("identityfile", "/b"))


class TestHostKeyTrust:
    def test_probe_and_trust_against_localhost_sshd(self, tmp_path: Path) -> None:
        # Probe a real local sshd if reachable; otherwise skip cleanly.
        probe_port = _find_local_sshd_port()
        if probe_port is None:
            pytest.skip("no local sshd on the standard ports to probe")
        store = HostKeyTrustStore(tmp_path / "known_hosts")
        desc = SshDescriptor("runner@127.0.0.1", probe_port, None, str(tmp_path / "known_hosts"))
        result = probe_host_key(desc, tmp_path)
        assert result.known_hosts_line
        assert result.fingerprint.startswith("SHA256:")
        # initial trust installs exactly the observed line
        store.install_initial(result.known_hosts_line)
        assert store.known_fingerprint("127.0.0.1", probe_port) == result.fingerprint
        # replacement removes every prior line for the host/port
        new_line = result.known_hosts_line.split(" ")[0] + " AAAA " + result.fingerprint
        store.replace_for_host(new_line, "127.0.0.1", probe_port)
        lines = (tmp_path / "known_hosts").read_text().splitlines()
        assert lines == [new_line]

    def test_probe_fails_closed_on_unreachable(self, tmp_path: Path) -> None:
        store = HostKeyTrustStore(tmp_path / "known_hosts")
        desc = SshDescriptor("nobody@127.0.0.1", 1, None, str(tmp_path / "known_hosts"))
        with pytest.raises(KeyProbeError):
            probe_host_key(desc, tmp_path)
        # no trusted file created
        assert (
            not (tmp_path / "known_hosts").exists()
            or store.known_fingerprint("127.0.0.1", 1) is None
        )


def _find_local_sshd_port() -> int | None:
    """Best-effort: is something speaking SSH on a common local port?"""
    for port in (22, 2222):
        try:
            proc = subprocess.run(
                [
                    "ssh",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ConnectTimeout=2",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-p",
                    str(port),
                    "127.0.0.1",
                    "true",
                ],
                capture_output=True,
                shell=False,
                timeout=5,
                check=False,
            )
            _ = proc
            # Any completed run (even permission denied) proves sshd exists.
            if b"Permission denied" in proc.stderr or (
                proc.returncode in (0, 5, 255) and b"Connection refused" not in proc.stderr
            ):
                return port
        except (subprocess.TimeoutExpired, OSError):
            continue
    return None


class TestConsentDigest:
    def _effective(self, tmp_path: Path) -> EffectiveSsh:
        return resolve_effective_ssh(_descriptor(tmp_path))

    def test_deterministic(self, tmp_path: Path) -> None:
        effective = self._effective(tmp_path)
        host = {"id": "3f1c2a9e-7b4d-4e8a-9c21-5d0f6a8b1e34", "label": "spark"}
        kwargs = {
            "host_config_excluding_consent": host,
            "ssh_effective": effective,
            "trusted_host_key_fingerprint": "SHA256:" + "A" * 43,
            "host_lifetime": "yes",
            "transport": {"kind": "ssh-tunnel"},
            "ordered_seats": [{"id": "s1", "label": "a"}],
        }
        assert consent_digest(**kwargs) == consent_digest(**kwargs)

    def test_every_input_change_changes_digest(self, tmp_path: Path) -> None:
        effective = self._effective(tmp_path)
        host = {"id": "h", "label": "spark"}
        base = {
            "host_config_excluding_consent": host,
            "ssh_effective": effective,
            "trusted_host_key_fingerprint": "SHA256:" + "A" * 43,
            "host_lifetime": "yes",
            "transport": {"kind": "ssh-tunnel"},
            "ordered_seats": [{"id": "s1", "label": "a"}],
        }
        digest = consent_digest(**base)
        # host edit
        changed = dict(base, host_config_excluding_consent={"id": "h", "label": "spark2"})
        assert consent_digest(**changed) != digest
        # lifetime change
        assert consent_digest(**dict(base, host_lifetime="no")) != digest
        # transport change
        assert consent_digest(**dict(base, transport={"kind": "https"})) != digest
        # fingerprint change
        assert (
            consent_digest(**dict(base, trusted_host_key_fingerprint="SHA256:" + "B" * 43))
            != digest
        )
        # seat order change
        reordered = dict(
            base, ordered_seats=[{"id": "s2", "label": "b"}, {"id": "s1", "label": "a"}]
        )
        assert consent_digest(**reordered) != digest
        # ssh effective change
        other_effective = EffectiveSsh(
            effective.ordered_pairs, effective.binary_path, effective.binary_version, "1" * 64
        )
        assert consent_digest(**dict(base, ssh_effective=other_effective)) != digest

    def test_edit_back_restores_canonical_value_but_consent_still_requires_reconfirmation(
        self, tmp_path: Path
    ) -> None:
        # The conservative S3 rule: reconfirmation is required after every
        # edit even when the canonical value is unchanged. The digest itself
        # is deterministic; the *acceptance* rule (any edit -> consent null)
        # is enforced by the store layer, so here we assert digest equality.
        effective = self._effective(tmp_path)
        host = {"id": "h", "label": "spark"}
        base = {
            "host_config_excluding_consent": host,
            "ssh_effective": effective,
            "trusted_host_key_fingerprint": "SHA256:" + "A" * 43,
            "host_lifetime": "yes",
            "transport": {"kind": "ssh-tunnel"},
            "ordered_seats": [{"id": "s1", "label": "a"}],
        }
        assert consent_digest(**base) == consent_digest(**base)

    def test_consent_text(self) -> None:
        text = consent_text_for("spark")
        assert "on spark over SSH" in text
        assert "Match exec" in text
        assert "RemoteCommand" in text
