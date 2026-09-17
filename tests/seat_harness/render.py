"""C2 remote-command renderer and C1 field validators (spec section 3.2).

SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later

This is a *reference* implementation of the spec's construction algorithm,
used by the harness to drive the normative scripts over a real SSH channel.
It is deliberately minimal: it implements exactly the C2 algorithm, the
validators the harness needs to feed adversarial vectors through, and the
Template C argv_sha256 byte layout. The production implementation (a later
task) must match this byte-for-byte; the golden tests in G3 pin that.
"""

from __future__ import annotations

import hashlib
import re
import secrets

# --- C1 validation classes (subset used by the harness) ---------------------

_UNIT_RE = re.compile(r"^[A-Za-z0-9_.@-]+$")
_MODEL_ID_RE = re.compile(r"^[A-Za-z0-9._/:+-]+$")
_OPTION_TOKEN_RE = re.compile(r"^--[a-z][a-z0-9-]*$|^-[A-Za-z0-9]$")
_ARGUMENT_VALUE_RE = re.compile(r"^[A-Za-z0-9._/:+=,@%-]+$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_LOCK_BASENAME_RE = re.compile(r"^endpoint-[0-9a-f]{64}\.lock$")


def validate_unit(value: str) -> str:
    if not (1 <= len(value) <= 255) or value.startswith("-") or not _UNIT_RE.match(value):
        raise ValueError(f"invalid unit: {value!r}")
    return value


def validate_model_id(value: str) -> str:
    if not (1 <= len(value) <= 512) or value.startswith("-") or not _MODEL_ID_RE.match(value):
        raise ValueError(f"invalid model id: {value!r}")
    return value


def validate_option_token(value: str) -> str:
    if not _OPTION_TOKEN_RE.match(value) or len(value) > 64:
        raise ValueError(f"invalid option token: {value!r}")
    return value


def validate_argument_value(value: str) -> str:
    if (
        not (1 <= len(value) <= 1024)
        or value.startswith("-")
        or not _ARGUMENT_VALUE_RE.match(value)
    ):
        raise ValueError(f"invalid argument value: {value!r}")
    return value


def validate_launch_argv(argv: list[str]) -> list[str]:
    """Template C launch_argv: element 0 is an absolute path, later elements
    must match exactly one of option-token or argument-value."""
    if not 1 <= len(argv) <= 128:
        raise ValueError("launch_argv length out of range")
    first = argv[0]
    if (
        not re.match(r"^/[A-Za-z0-9_./+@-]+$", first)
        or ".." in first.split("/")
        or first.endswith("/")
    ):
        raise ValueError(f"launch_argv[0] not an absolute path: {first!r}")
    for i, element in enumerate(argv[1:], start=1):
        is_option = bool(_OPTION_TOKEN_RE.match(element))
        is_argument = bool(_ARGUMENT_VALUE_RE.match(element)) and not element.startswith("-")
        if is_option == is_argument:  # matches both or neither -> reject
            raise ValueError(f"launch_argv[{i}] ambiguous or invalid: {element!r}")
    return argv


def validate_nonce(value: str) -> str:
    if not _NONCE_RE.match(value):
        raise ValueError(f"invalid nonce: {value!r}")
    return value


def validate_lock_basename(value: str) -> str:
    if not _LOCK_BASENAME_RE.match(value):
        raise ValueError(f"invalid lock basename: {value!r}")
    return value


# --- C2 construction algorithm ----------------------------------------------


def sq(s: str) -> str:
    """Single-quote a word per the spec: ' + s.replace("'", "'\\''") + '."""
    return "'" + s.replace("'", "'\\''") + "'"


def render(words: list[str]) -> str:
    return " ".join(sq(w) for w in words)


def remote_command(script: str, args: list[str]) -> str:
    """render(['sh', '-c', script, 'testudo'] + args)."""
    return render(["sh", "-c", script, "testudo", *args])


def local_ssh_argv(destination: str, remote_command_str: str) -> list[str]:
    """Local SSH argv with the mandatory options from section 3.1.

    The harness uses a real sshd, so StrictHostKeyChecking here is
    accept-new against the harness's own known-hosts file — production
    command connections use =yes (the harness's G4/S2 checks assert the
    probe/command split separately).
    """
    return [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "UserKnownHostsFile=known_hosts",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "RemoteCommand=none",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ForwardX11=no",
        "-o",
        "ForwardX11Trusted=no",
        "-o",
        "RequestTTY=no",
        destination,
        remote_command_str,
    ]


# --- Template C identity bytes ----------------------------------------------


def argv_sha256(launch_argv: list[str]) -> str:
    """SHA-256 over each UTF-8 element followed by one NUL byte (C3).

    The final argument is NUL-terminated; there is no additional trailing
    empty element — exactly matching Linux /proc/<pid>/cmdline.
    """
    h = hashlib.sha256()
    for element in launch_argv:
        h.update(element.encode("utf-8") + b"\x00")
    return h.hexdigest()


def new_nonce() -> str:
    """32 lowercase hex characters from 128 random bits."""
    return secrets.token_hex(16)


def lock_basename(lock_key_hex: str) -> str:
    return f"endpoint-{lock_key_hex}.lock"
