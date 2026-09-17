"""Byte-exact extraction of the normative shell scripts from the spec.

SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later

Spec section 8 requires the harness to execute every normative script
**exactly as written**. This module extracts the constant ``sh`` blocks
(GUARD_V1, LAUNCH_V1, C_PID_V1, LOG_TAIL_V1) directly from
``docs/SEAT_CONTROL_SPEC.md`` at collection time and pins their SHA-256
digests, and extracts the inline constant ``EXEC_V1`` from the spec prose
(``set\n-eu; exec "$@"`` — the line break inside the identifier is a spec
typo; the harness normalizes it to ``set -eu; exec "$@"``, asserts the raw
spec fragment byte-for-byte, and pins the normalized form's digest).

If the spec text changes, the digest pins fail first and the reviewer must
consciously re-pin — a normative script change without a passing harness
update cannot slip through silently.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Final

SPEC_PATH = Path(__file__).resolve().parents[2] / "docs" / "SEAT_CONTROL_SPEC.md"

# Digests of the normative scripts, in spec order: GUARD_V1, LAUNCH_V1,
# C_PID_V1 (Revision 5 amendment: single-dash process-group kills, dash-
# compatible; verify() distinguishes absent (1) from mismatched (2) identity
# so post-TERM disappearance is success), LOG_TAIL_V1, and the normalized
# inline EXEC_V1 constant.
EXPECTED_DIGESTS: Final[dict[str, str]] = {
    "GUARD_V1": "6653a21821d6f3dfdc32120f2ae35d9fe5e7420872eff16f24370ec54d0a1e9e",
    "LAUNCH_V1": "b81dbd058c5a6ae00db951fc60362565fc46604b0739a189ccec4db0e5e66239",
    "C_PID_V1": "7246beede3e472b2bbd0dae73ec05079869cc30f5bd392575cf833aceeaefaea",
    "LOG_TAIL_V1": "a152af6d6a8ad7f19a33572e31ff76a34187a9cb6c7668eafe456618edbb1283",
    "EXEC_V1": "81e844264933390cf63746bd9a90e514479dd1a7aa0b5eaf157f47c528bf6a69",
}

# EXEC_V1 is inline in the spec prose. The spec line break inside the
# identifier ("set\n-eu; exec \"$@\"") is normalized to a space; the
# normalized form is what the harness executes and what the digest pins.
EXEC_V1_NORMALIZED: Final[str] = 'set -eu; exec "$@"'
EXEC_V1_SPEC_TEXT: Final[str] = 'set\n-eu; exec "$@"'

_BLOCK_RE = re.compile(r"```sh\n(.*?)```", re.S)
_EXEC_V1_RE = re.compile(r"constant `EXEC_V1` is `([^`]*)`")
_NAMES_IN_ORDER = ("GUARD_V1", "LAUNCH_V1", "C_PID_V1", "LOG_TAIL_V1")


def extract_normative_scripts(spec_path: Path = SPEC_PATH) -> dict[str, str]:
    """Extract the four normative sh blocks byte-exactly, in spec order."""
    text = spec_path.read_text(encoding="utf-8")
    blocks = _BLOCK_RE.findall(text)
    if len(blocks) < len(_NAMES_IN_ORDER):
        raise AssertionError(
            f"expected at least {len(_NAMES_IN_ORDER)} sh blocks in spec, found {len(blocks)}"
        )
    scripts = dict(zip(_NAMES_IN_ORDER, blocks, strict=True))
    for name, body in scripts.items():
        if not body.startswith("set -eu"):
            raise AssertionError(f"{name} block does not start with 'set -eu'")
    scripts["EXEC_V1"] = extract_exec_v1(spec_path)[1]
    return scripts


def extract_exec_v1(spec_path: Path = SPEC_PATH) -> tuple[str, str]:
    """Extract EXEC_V1 from the spec prose: (raw spec fragment, normalized).

    The raw fragment is asserted byte-for-byte against ``EXEC_V1_SPEC_TEXT``
    (the identifier's embedded line break is a known spec typo); the
    normalized form collapses it to the executable ``set -eu; exec "$@"``.
    """
    text = spec_path.read_text(encoding="utf-8")
    match = _EXEC_V1_RE.search(text)
    if match is None:
        raise AssertionError(
            "EXEC_V1 not found in spec prose (expected 'constant `EXEC_V1` is `...`)"
        )
    raw = match.group(1)
    if raw != EXEC_V1_SPEC_TEXT:
        raise AssertionError(
            f"EXEC_V1 spec fragment drifted: {raw!r} != pinned {EXEC_V1_SPEC_TEXT!r}"
        )
    normalized = " ".join(raw.split())
    if normalized != EXEC_V1_NORMALIZED:
        raise AssertionError(
            f"EXEC_V1 normalization drifted: {normalized!r} != {EXEC_V1_NORMALIZED!r}"
        )
    return raw, normalized


def digest_of(script_text: str) -> str:
    return hashlib.sha256(script_text.encode("utf-8")).hexdigest()


def pin_current_digests() -> dict[str, str]:
    """Compute current digests (used once by the maintainer to update pins)."""
    return {name: digest_of(body) for name, body in extract_normative_scripts().items()}


def assert_pins_match() -> dict[str, tuple[str, str]] | None:
    """Return {name: (actual, expected)} for drifted pins, or None when all match."""
    scripts = extract_normative_scripts()
    drifted = {
        name: (digest_of(scripts[name]), EXPECTED_DIGESTS[name])
        for name in (*_NAMES_IN_ORDER, "EXEC_V1")
        if digest_of(scripts[name]) != EXPECTED_DIGESTS[name]
    }
    return drifted or None
