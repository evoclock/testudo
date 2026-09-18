# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""L1/L2/U1 unit tests: local lock semantics, guard protocol parsing, and
the lingering gate."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

from testudo.seats.guard import (
    GuardController,
    LocalGuardError,
    LocalLock,
    _exact_trailer_rc,
    _operation_output,
    _parse_last_trailer,
)
from testudo.seats.lifetime import (
    LingerObservation,
    linger_probe_remote_command,
    parse_linger_output,
    start_gate,
)
from testudo.seats.render import new_nonce, remote_command
from testudo.seats.ssh import SshDescriptor


class TestLocalLock:
    def test_acquire_release_roundtrip(self, tmp_path: Path) -> None:
        lock = LocalLock(tmp_path / "endpoint-aa.lock")
        lock.acquire()
        lock.release()
        # re-acquirable after release
        lock.acquire()
        lock.release()

    def test_creates_file_0600(self, tmp_path: Path) -> None:
        path = tmp_path / "locks" / "endpoint-bb.lock"
        lock = LocalLock(path)
        lock.acquire()
        try:
            assert os.stat(path).st_mode & 0o777 == 0o600
        finally:
            lock.release()

    def test_symlink_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "elsewhere"
        target.write_text("")
        path = tmp_path / "endpoint-cc.lock"
        path.symlink_to(target)
        lock = LocalLock(path)
        with pytest.raises(LocalGuardError):
            lock.acquire()

    def test_contention_times_out_at_ten_seconds(self, tmp_path: Path) -> None:
        path = tmp_path / "endpoint-dd.lock"
        first = LocalLock(path)
        first.acquire()
        second = LocalLock(path)
        started = time.monotonic()
        with pytest.raises(LocalGuardError):
            second.acquire(wait_seconds=0.5)  # shortened for test speed
        elapsed = time.monotonic() - started
        assert elapsed >= 0.4

    def test_exclusive_flock_across_processes(self, tmp_path: Path) -> None:
        path = tmp_path / "endpoint-ee.lock"
        lock = LocalLock(path)
        lock.acquire()
        # another process cannot flock while we hold it (proves exclusivity)
        script = (
            "import fcntl, sys\n"
            f"fd = open({str(path)!r}, 'a+')\n"
            "try:\n"
            "    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
            "    print('acquired')\n"
            "except OSError:\n"
            "    print('busy')\n"
        )
        proc = subprocess.run(
            [os.sys.executable, "-c", script], capture_output=True, text=True, timeout=10
        )
        assert proc.stdout.strip() == "busy"
        lock.release()
        proc = subprocess.run(
            [os.sys.executable, "-c", script], capture_output=True, text=True, timeout=10
        )
        assert proc.stdout.strip() == "acquired"

    def test_release_on_crash(self, tmp_path: Path) -> None:
        path = tmp_path / "endpoint-ff.lock"
        holder = subprocess.Popen(
            [
                os.sys.executable,
                "-c",
                f"import fcntl, os; fd = os.open({str(path)!r}, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); "
                "fcntl.flock(fd, fcntl.LOCK_EX); "
                "import signal; os.kill(os.getpid(), signal.SIGKILL)",
            ]
        )
        holder.wait()
        # no age takeover needed: the OS released the flock on process death
        lock = LocalLock(path)
        lock.acquire(wait_seconds=2)
        lock.release()


class TestTrailerParsing:
    def test_exact_trailer(self) -> None:
        nonce = new_nonce()
        assert _exact_trailer_rc(f"TESTUDO_OPERATION_EXIT {nonce} 0", nonce) == 0
        assert _exact_trailer_rc(f"TESTUDO_OPERATION_EXIT {nonce} 17", nonce) == 17

    def test_wrong_nonce_rejected(self) -> None:
        nonce = new_nonce()
        other = new_nonce()
        assert _exact_trailer_rc(f"TESTUDO_OPERATION_EXIT {other} 0", nonce) is None

    def test_forged_marker_in_operation_output_stays_ordinary(self) -> None:
        nonce = new_nonce()
        stdout = (
            "server output\n"
            f"TESTUDO_OPERATION_EXIT {nonce} 0\n"  # forged, mid-stream
            "more output\n"
            f"TESTUDO_OPERATION_EXIT {nonce} 5\n"  # genuine last trailer
        )
        assert _parse_last_trailer(stdout, nonce) == 5

    def test_protocol_shaped_text_after_trailer_fails_closed(self) -> None:
        nonce = new_nonce()
        stdout = f"out\nTESTUDO_OPERATION_EXIT {nonce} 0\nTESTUDO_LOCKED {nonce}\n"
        assert _parse_last_trailer(stdout, nonce) is None

    def test_malformed_rc_fails_closed(self) -> None:
        nonce = new_nonce()
        stdout = f"TESTUDO_OPERATION_EXIT {nonce} notanumber\n"
        assert _parse_last_trailer(stdout, nonce) is None

    def test_operation_output_excludes_protocol_lines(self) -> None:
        nonce = new_nonce()
        stdout = f"TESTUDO_LOCKED {nonce}\nhello\nTESTUDO_OPERATION_EXIT {nonce} 3\n"
        assert _operation_output(stdout, nonce) == "hello"


class TestLinger:
    def test_probe_command_shape(self) -> None:
        rendered = linger_probe_remote_command("user")
        expected = remote_command(
            'set -eu; exec "$@"',
            ["loginctl", "show-user", "user", "--property=Linger", "--value"],
        )
        assert rendered == expected
        assert "enable-linger" not in rendered

    def test_parse_yes_no(self) -> None:
        assert parse_linger_output("yes\n", "", 0).value == "yes"
        assert parse_linger_output("no\n", "", 0).value == "no"
        assert parse_linger_output(" yes \n", "", 0).value == "yes"

    def test_parse_unknown_cases(self) -> None:
        assert parse_linger_output("", "", 1).value == "unknown"
        assert parse_linger_output("maybe\n", "", 0).value == "unknown"
        assert parse_linger_output("yes\nno\n", "", 0).value == "unknown"
        assert parse_linger_output("", "", None).value == "unknown"
        # missing user manager: logind error text
        assert parse_linger_output("", "user manager missing\n", 1).value == "unknown"

    def test_start_gate(self) -> None:
        allowed, warning = start_gate(LingerObservation("yes"))
        assert allowed and warning is None
        allowed, warning = start_gate(LingerObservation("no"))
        assert not allowed and warning == "service may stop when this session ends"
        allowed, warning = start_gate(LingerObservation("unknown"))
        assert not allowed and warning == "service may stop when this session ends"


class TestGuardControllerParsing:
    """Protocol-loop unit checks without a live SSH channel (the harness's
    G1-G4 tests exercise the real channel; these pin the controller's
    fail-closed parsing)."""

    def _controller(self) -> GuardController:
        descriptor = SshDescriptor("localhost", None, None, "/tmp/none")
        return GuardController(descriptor, "endpoint-" + "0" * 64 + ".lock", new_nonce())

    def test_ssh_argv_remote_command_appears_exactly_once(self) -> None:
        """Regression (BLK-1): ConnectTimeout is inserted before the
        destination and the remote command appears exactly once. A doubled
        remote element made GUARD_V1 re-exec itself, so Template C launches
        inherited the guard script as trailing argv and always exited 78."""
        controller = self._controller()
        argv = controller._ssh_argv("REMOTE COMMAND")
        assert argv.count("REMOTE COMMAND") == 1
        assert argv[-1] == "REMOTE COMMAND"
        assert argv[-2] == "localhost"
        assert "ConnectTimeout=10" in argv
        assert argv[argv.index("ConnectTimeout=10") - 1] == "-o"

    def test_drive_protocol_reconcile_receives_operation_output(self) -> None:
        """Regression (BLK-5): reconciliation receives the operation output
        with the exact protocol lines stripped, so Template C can find its
        single TESTUDO_PID line rather than the LOCKED/trailer lines too."""
        nonce = new_nonce()
        script = (
            "import sys\n"
            f"sys.stdout.write('TESTUDO_LOCKED {nonce}\\n'); sys.stdout.flush()\n"
            "line = sys.stdin.readline()\n"
            f"assert line.strip() == 'GO {nonce}'\n"
            "sys.stdout.write('hello\\n')\n"
            f"sys.stdout.write('TESTUDO_OPERATION_EXIT {nonce} 0\\n'); sys.stdout.flush()\n"
            "sys.stdin.readline()\n"
        )
        proc = subprocess.Popen(
            [os.sys.executable, "-c", script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        seen: list[str] = []
        controller = GuardController(
            SshDescriptor("localhost", None, None, "/tmp/none"),
            "endpoint-" + "0" * 64 + ".lock",
            nonce,
            reconcile=seen.append,
        )
        outcome = controller._drive_protocol(proc, timeout=10)
        assert outcome.rc_trailer == 0
        assert seen == ["hello"]


class TestTunnelPollD2Checks:
    """MED-5: tunnel/HTTPS polling applies the D2 status/content-type/cap
    rules (T1)."""

    def test_helpers(self) -> None:
        from testudo.seats.transport import _http_header, _http_status_line, _json_content_type

        assert _http_status_line(b"HTTP/1.0 200 OK\r\n\r\n{}") == 200
        assert _http_status_line(b"HTTP/1.0 404 Not Found\r\n\r\n") == 404
        assert _http_status_line(b"garbage") is None
        assert _json_content_type("application/json; charset=utf-8") is True
        assert _json_content_type("text/html") is False
        assert (
            _http_header(
                b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n", b"content-type"
            )
            == "application/json"
        )
        assert _http_header(b"HTTP/1.0 200 OK\r\n\r\n", b"content-type") == ""

    def test_tunnel_response_classification(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from testudo.seats import transport as transport_mod

        class FakeProc:
            def __init__(self, stdout: bytes) -> None:
                self.stdout = stdout
                self.returncode = 0

        poller = transport_mod.EndpointPoller()
        body = b'{"data": [{"id": "example-model"}]}'

        def fake_run(argv, *args: object, **kwargs: object) -> FakeProc:
            return FakeProc(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n" + body)

        monkeypatch.setattr(transport_mod.subprocess, "run", fake_run)
        from testudo.seats.ssh import SshDescriptor

        descriptor = SshDescriptor("fixture@127.0.0.1", 2222, None, "/tmp/kh")
        observation = poller.poll(
            {"kind": "ssh-tunnel"}, "127.0.0.1", 8000, "example-model", descriptor=descriptor
        )
        assert observation.models == ("example-model",)

        def fake_run_text(argv, *args: object, **kwargs: object) -> FakeProc:
            return FakeProc(b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" + body)

        monkeypatch.setattr(transport_mod.subprocess, "run", fake_run_text)
        observation = poller.poll(
            {"kind": "ssh-tunnel"}, "127.0.0.1", 8000, "example-model", descriptor=descriptor
        )
        assert observation.endpoint_state == "invalid"
        assert observation.detail == "wrong-content-type"

        def fake_run_status(argv, *args: object, **kwargs: object) -> FakeProc:
            return FakeProc(b"HTTP/1.0 404 Not Found\r\n\r\n")

        monkeypatch.setattr(transport_mod.subprocess, "run", fake_run_status)
        observation = poller.poll(
            {"kind": "ssh-tunnel"}, "127.0.0.1", 8000, "example-model", descriptor=descriptor
        )
        assert observation.endpoint_state == "invalid"
        assert "404" in observation.detail

        def fake_run_401(argv, *args: object, **kwargs: object) -> FakeProc:
            return FakeProc(b"HTTP/1.0 401 Unauthorized\r\n\r\n")

        monkeypatch.setattr(transport_mod.subprocess, "run", fake_run_401)
        observation = poller.poll(
            {"kind": "ssh-tunnel"}, "127.0.0.1", 8000, "example-model", descriptor=descriptor
        )
        assert observation.endpoint_state == "unauthorized"

        def fake_run_oversize(argv, *args: object, **kwargs: object) -> FakeProc:
            return FakeProc(
                b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n"
                + b"x" * (1024 * 1024 + 10)
            )

        monkeypatch.setattr(transport_mod.subprocess, "run", fake_run_oversize)
        observation = poller.poll(
            {"kind": "ssh-tunnel"}, "127.0.0.1", 8000, "example-model", descriptor=descriptor
        )
        assert observation.endpoint_state == "indeterminate"
        assert observation.detail == "overflow"
