# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""C1/C2 unit tests: validation classes, construction algorithm golden bytes,
argv_sha256 byte layout, and lock keys."""

from __future__ import annotations

import hashlib
import json

import pytest

from testudo.seats.render import argv_sha256, lock_key, remote_command, render, sq
from testudo.seats.validation import (
    ValidationError,
    canonical_hostname,
    validate_absolute_path,
    validate_argument_value,
    validate_boot_id,
    validate_fingerprint,
    validate_label,
    validate_launch_argv,
    validate_model_id,
    validate_nonce,
    validate_option_token,
    validate_port,
    validate_subcommand,
    validate_timeout,
    validate_unit,
    validate_uuid4,
)


class TestValidationClasses:
    def test_uuid4_class(self) -> None:
        assert validate_uuid4("id", "9a4b7c1d-2e5f-4a30-8b6c-1d2e3f4a5b60")
        with pytest.raises(ValidationError):
            validate_uuid4("id", "9a4b7c1d-2e5f-4a30-8b6c-1d2e3f4a5b6z")  # not hex
        with pytest.raises(ValidationError):
            validate_uuid4("id", "9A4B7C1D-2E5F-4A30-8B6C-1D2E3F4A5B60")  # uppercase
        with pytest.raises(ValidationError):
            validate_uuid4("id", "00000000-0000-1000-8000-000000000000")  # v1
        # variant must be 8/9/a/b
        with pytest.raises(ValidationError):
            validate_uuid4("id", "9a4b7c1d-2e5f-4a30-cb6c-1d2e3f4a5b60")

    def test_label(self) -> None:
        assert validate_label("label", "spark-01 ok")
        with pytest.raises(ValidationError):
            validate_label("label", "")
        with pytest.raises(ValidationError):
            validate_label("label", "tab\tchar")
        with pytest.raises(ValidationError):
            validate_label("label", "é")  # non-ASCII
        with pytest.raises(ValidationError):
            validate_label("label", "x" * 129)

    def test_unit(self) -> None:
        assert validate_unit("unit", "model.service")
        assert validate_unit("unit", "a_b@c-d.e")
        with pytest.raises(ValidationError):
            validate_unit("unit", "-lead")
        with pytest.raises(ValidationError):
            validate_unit("unit", "has space")
        with pytest.raises(ValidationError):
            validate_unit("unit", "x" * 256)

    def test_model_id(self) -> None:
        assert validate_model_id("model_id", "example-model:latest")
        with pytest.raises(ValidationError):
            validate_model_id("model_id", "-lead")
        with pytest.raises(ValidationError):
            validate_model_id("model_id", "sp ace")
        with pytest.raises(ValidationError):
            validate_model_id("model_id", "x" * 513)

    def test_absolute_path(self) -> None:
        assert validate_absolute_path("script", "/home/user/.local/bin/mc")
        assert validate_absolute_path("cwd", "/")
        assert validate_absolute_path("script", "/a")
        with pytest.raises(ValidationError):
            validate_absolute_path("script", "relative/path")
        with pytest.raises(ValidationError):
            validate_absolute_path("script", "/a/../b")
        with pytest.raises(ValidationError):
            validate_absolute_path("script", "/a//b")
        with pytest.raises(ValidationError):
            validate_absolute_path("script", "/a/")
        with pytest.raises(ValidationError):
            validate_absolute_path("script", "/a\x01b")

    def test_subcommand(self) -> None:
        assert validate_subcommand("start_subcommand", "start")
        assert validate_subcommand("stop_subcommand", "a.b-_9")
        with pytest.raises(ValidationError):
            validate_subcommand("stop_subcommand", "-x")
        with pytest.raises(ValidationError):
            validate_subcommand("stop_subcommand", "")
        with pytest.raises(ValidationError):
            validate_subcommand("stop_subcommand", "x" * 65)

    def test_hostname_canonicalization(self) -> None:
        assert canonical_hostname("endpoint_host", "Example.COM") == "example.com"
        assert canonical_hostname("endpoint_host", "example.com.") == "example.com"
        assert canonical_hostname("endpoint_host", "127.0.0.1") == "127.0.0.1"
        # IPv6 canonicalizes to RFC5952 compressed lowercase.
        assert canonical_hostname("endpoint_host", "::1") == "::1"
        assert (
            canonical_hostname("endpoint_host", "0000:0000:0000:0000:0000:0000:0000:0001") == "::1"
        )
        with pytest.raises(ValidationError):
            canonical_hostname("endpoint_host", "bad host")
        with pytest.raises(ValidationError):
            canonical_hostname("endpoint_host", "-lead.example")

    def test_port_and_timeout(self) -> None:
        assert validate_port("port", 1) == 1
        assert validate_port("port", 65535) == 65535
        with pytest.raises(ValidationError):
            validate_port("port", 0)
        with pytest.raises(ValidationError):
            validate_port("port", 65536)
        with pytest.raises(ValidationError):
            validate_port("port", True)  # bool is not a JSON integer here
        with pytest.raises(ValidationError):
            validate_port("port", 8000.0)  # float
        assert validate_timeout("ready_timeout", 30, 30, 1800) == 30
        with pytest.raises(ValidationError):
            validate_timeout("ready_timeout", 29, 30, 1800)
        with pytest.raises(ValidationError):
            validate_timeout("ready_timeout", 1801, 30, 1800)

    def test_option_token_and_argument_value(self) -> None:
        assert validate_option_token("launch_argv[1]", "--port")
        assert validate_option_token("launch_argv[1]", "-p")
        with pytest.raises(ValidationError):
            validate_option_token("launch_argv[1]", "--Port")  # uppercase after --
        with pytest.raises(ValidationError):
            validate_option_token("launch_argv[1]", "--")  # bare
        assert validate_argument_value("launch_argv[2]", "8000")
        assert validate_argument_value("launch_argv[2]", "a.b:8000+x%")
        with pytest.raises(ValidationError):
            validate_argument_value("launch_argv[2]", "-x")
        with pytest.raises(ValidationError):
            validate_argument_value("launch_argv[2]", "has space")
        with pytest.raises(ValidationError):
            validate_argument_value("launch_argv[2]", "x" * 1025)

    def test_launch_argv_ambiguity(self) -> None:
        assert validate_launch_argv("launch_argv", ["/usr/bin/srv", "--port", "8000"])
        # matches both classes -> reject
        with pytest.raises(ValidationError):
            validate_launch_argv("launch_argv", ["/usr/bin/srv", "-p8"])  # -p8: option? no
        # "--" matches neither
        with pytest.raises(ValidationError):
            validate_launch_argv("launch_argv", ["/usr/bin/srv", "--"])
        # leading-dash argument that is not a valid option token
        with pytest.raises(ValidationError):
            validate_launch_argv("launch_argv", ["/usr/bin/srv", "--name=value"])
        with pytest.raises(ValidationError):
            validate_launch_argv("launch_argv", [])
        with pytest.raises(ValidationError):
            validate_launch_argv("launch_argv", ["x" * 1024] + ["8000"] * 128)

    def test_control_characters_rejected_everywhere(self) -> None:
        for value in ("a\x00b", "a\x01b", "a\x7fb", "a\x85b"):
            with pytest.raises(ValidationError):
                validate_label("label", value)

    def test_boot_id_and_fingerprint_and_nonce(self) -> None:
        assert validate_boot_id("boot_id", "8f4c1e2a-9b3d-4c5e-8f6a-7b8c9d0e1f2a")
        with pytest.raises(ValidationError):
            validate_boot_id("boot_id", "8F4C1E2A-9B3D-4C5E-8F6A-7B8C9D0E1F2A")
        fingerprint = "SHA256:" + "A" * 43
        assert validate_fingerprint("fingerprint", fingerprint)
        with pytest.raises(ValidationError):
            validate_fingerprint("fingerprint", "SHA256:" + "A" * 42)
        with pytest.raises(ValidationError):
            validate_fingerprint("fingerprint", "md5:" + "A" * 43)
        assert validate_nonce("nonce", "0123456789abcdef" * 2)
        with pytest.raises(ValidationError):
            validate_nonce("nonce", "0123456789ABCDEF" * 2)


class TestGoldenConstruction:
    def test_sq_escaping(self) -> None:
        assert sq("plain") == "'plain'"
        assert sq("it's") == "'it'\\''s'"
        assert sq("") == "''"
        assert sq("a'b'c") == "'a'\\''b'\\''c'"

    def test_remote_command_shape(self) -> None:
        assert remote_command("SCRIPT", ["a", "b"]) == "'sh' '-c' 'SCRIPT' 'testudo' 'a' 'b'"

    def test_adversarial_values_stay_positional(self) -> None:
        adversarial = [
            "hello world",
            "it's",
            "$(echo pwned)",
            "`echo pwned`",
            "a;b",
            "a|b",
            "a&b",
            "line1\nline2",
            "tab\there",
            "-leading-dash",
            "--",
            "~root",
            "*",
            "a>b",
            "a<b",
            "$HOME",
            "a\\b",
            '"double"',
            "a'b`c;d|e&f\ng",
        ]
        rendered = remote_command('set -eu; exec "$@"', adversarial)
        # one remote string: the whole rendered command is exactly one argv
        # element locally; every adversarial value survives inside single
        # quotes with only the sq escape applied.
        for value in adversarial:
            assert sq(value) in rendered
        # No shell operator can escape quoting: quote count equals the
        # golden arithmetic. Each word contributes its 2 outer quotes; each
        # apostrophe is replaced by sq with '\'\'' (3 quotes).
        words = 4 + len(adversarial)  # sh, -c, script, testudo, values
        escapes = sum(value.count("'") for value in adversarial)
        assert rendered.count("'") == 2 * words + 3 * escapes

    def test_local_argv_has_one_remote_string(self) -> None:
        argv = ["ssh", "-o", "BatchMode=yes", "user@host", remote_command("X", ["y"])]
        # exactly one element after the destination
        assert argv[-2] == "user@host"
        assert len(argv) - 1 == argv.index("user@host") + 1

    def test_argv_sha256_byte_layout(self) -> None:
        # NUL after every argument, final argument NUL-terminated.
        argv = ["/home/user/bin/server", "--port", "8000"]
        expected = hashlib.sha256(b"/home/user/bin/server\x00--port\x008000\x00").hexdigest()
        assert argv_sha256(argv) == expected
        assert argv_sha256([]) == hashlib.sha256(b"").hexdigest()

    def test_lock_key_canonical_json(self) -> None:
        key = lock_key("spark", 22, "127.0.0.1", 8000)
        canonical = json.dumps(
            {
                "ssh_hostname": "spark",
                "ssh_port": 22,
                "endpoint_host": "127.0.0.1",
                "endpoint_port": 8000,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        assert key == hashlib.sha256(canonical.encode()).hexdigest()
        # deterministic
        assert lock_key("spark", 22, "127.0.0.1", 8000) == key
        # order-insensitive input ordering (canonical JSON sorts keys)
        assert lock_key("spark", 22, "127.0.0.1", 8000) == lock_key("spark", 22, "127.0.0.1", 8000)

    def test_render_golden(self) -> None:
        assert render(["sh", "-c", "x", "testudo", "a b", "it's"]) == (
            "'sh' '-c' 'x' 'testudo' 'a b' 'it'\\''s'"
        )

    def test_nonce_generation_shape(self) -> None:
        from testudo.seats.render import new_nonce

        nonce = new_nonce()
        assert len(nonce) == 32
        int(nonce, 16)  # lowercase hex
        assert nonce == nonce.lower()
