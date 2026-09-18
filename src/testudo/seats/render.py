# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""C2 remote-command construction algorithm (spec section 3.2).

One construction algorithm, byte-for-byte; no alternative helper or
multi-argument interpretation is permitted. The local SSH argv carries
exactly one final remote-command element. Shell operators occur only inside
constant scripts and are never represented as allegedly quoted operator
words.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Final

from testudo.seats.validation import (
    validate_lock_basename,
    validate_nonce,
)

MAX_OUTPUT_BYTES: Final = 1024 * 1024  # hard 1 MiB read cap on remote output


def sq(s: str) -> str:
    """Single-quote a word per the spec: ``'`` + replace(s, "'", "'\\''") + ``'``."""
    return "'" + s.replace("'", "'\\''") + "'"


def render(words: list[str]) -> str:
    """join([sq(w) for w in words], " ")."""
    return " ".join(sq(w) for w in words)


def remote_command(script: str, args: list[str]) -> str:
    """render(['sh', '-c', script, 'testudo'] + args)."""
    return render(["sh", "-c", script, "testudo", *args])


def new_nonce() -> str:
    """32 lowercase hexadecimal characters from 128 random bits."""
    return secrets.token_hex(16)


def lock_basename(lock_key_hex: str) -> str:
    """Exactly ``endpoint-<64 lowercase hex>.lock``."""
    name = f"endpoint-{lock_key_hex}.lock"
    validate_lock_basename("lock-basename", name)
    return name


def validate_nonce_or_raise(nonce: str) -> str:
    return validate_nonce("nonce", nonce)


def argv_sha256(launch_argv: list[str]) -> str:
    """SHA-256 over each UTF-8 element followed by one NUL byte (C3).

    The final argument is NUL-terminated; there is no additional trailing
    empty element — exactly matching Linux ``/proc/<pid>/cmdline``.
    """
    digest = hashlib.sha256()
    for element in launch_argv:
        digest.update(element.encode("utf-8") + b"\x00")
    return digest.hexdigest()


def lock_key(ssh_hostname: str, ssh_port: int, endpoint_host: str, endpoint_port: int) -> str:
    """SHA-256 of canonical JSON ``{ssh_hostname, ssh_port, endpoint_host,
    endpoint_port}`` — the local and remote lock key (section 3.3)."""
    import json

    canonical = json.dumps(
        {
            "ssh_hostname": ssh_hostname,
            "ssh_port": ssh_port,
            "endpoint_host": endpoint_host,
            "endpoint_port": endpoint_port,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
