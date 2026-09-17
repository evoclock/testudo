"""G3 — C2 quoting golden adversarial vectors (C2 / section 7 C2 row).

SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later

Every golden vector is rendered with the exact C2 algorithm, sent through a
real SSH channel to the fixture sshd, and executed as
``sh -c <script> testudo <vector>``; the remote argv is printed back and must
equal the original vector byte-for-byte. Shell operators inside the vector
(spaces, quotes, $(), backticks, semicolons, leading dashes, newlines, globs,
pipes, redirects, --) must remain positional data, never interpretation.

Runs on both fixture backends (macOS native sshd included) because quoting
is a property of the rendered string, not of Linux.
"""

from __future__ import annotations

import pytest

from .conftest import GuardEnv
from .render import remote_command

pytestmark = pytest.mark.seat_harness

# POSIX sh argv printer: prints each argument as [<arg>] on one line.
ARGV_PRINTER = (
    'n=$#; i=1; while [ $i -le $n ]; do eval v=\\"\\${$i}\\"; '
    'printf "[%s]" "$v"; i=$((i+1)); done; printf "\\n"'
)

GOLDEN_VECTORS = [
    "plain",
    "two words",
    "single'quote",
    'double"quote',
    "back\\slash",
    "dollar$(echo pwned)",
    "back`tick`",
    "semi;colon",
    "-leading-dash",
    "line1\nline2",
    "tab\there",
    "$HOME",
    "~root",
    "glob*star",
    "pipe|and&&amp",
    "redirect>out<in",
    "quote'and$(cmd)and`cmd`",
    "--",
    "-",
    "ünïcödé-ß",
    "'\\''",  # the sq() escape sequence itself
    "a'b'c\"d\"e\\f$g`h`i;j|k&l<m>n(o)p[q]r{s}t",
]


@pytest.fixture
def runner(guard_env: GuardEnv):
    return guard_env.ssh_runner()


@pytest.mark.parametrize("vector", GOLDEN_VECTORS)
def test_g3_vector_round_trips_without_interpretation(runner, vector: str) -> None:
    remote = remote_command(ARGV_PRINTER, [vector])
    result = runner.run(remote, timeout=30)
    assert result.exit_code == 0, f"remote sh failed: {result.stderr[:200]}"
    expected = f"[{vector}]"
    assert result.stdout.strip("\n") == expected, (
        f"vector {vector!r} was interpreted or mangled: got {result.stdout!r}"
    )


def test_g3_multiple_positional_args_round_trip(runner) -> None:
    """The GUARD_V1 argument shape (lock, nonce, program, args...) survives."""
    args = [
        "endpoint-" + "a" * 64 + ".lock",
        "0123456789abcdef0123456789abcdef",
        "/bin/echo",
        "hello world",
        "it's",
        "$(nope)",
    ]
    remote = remote_command(ARGV_PRINTER, args)
    result = runner.run(remote, timeout=30)
    assert result.exit_code == 0
    assert result.stdout.strip("\n") == "".join(f"[{a}]" for a in args)


def test_g3_local_argv_has_exactly_one_remote_string(runner) -> None:
    """C2: the local SSH argv carries exactly one final remote-command element."""
    from .render import local_ssh_argv

    argv = local_ssh_argv("fixture@127.0.0.1", remote_command(ARGV_PRINTER, ["x y"]))
    # Everything after the destination is exactly one element.
    dest_index = argv.index("fixture@127.0.0.1")
    assert len(argv) - dest_index == 2, f"local argv must end with one remote string: {argv}"
