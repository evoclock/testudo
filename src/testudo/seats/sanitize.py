# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""R2 output boundary: before renderer display, all remote/provider output
is processed as bytes with invalid UTF-8 replaced, ANSI escape sequences and
C0/C1 controls removed (preserving line feed), known credential forms
redacted, and then truncated to 4 KiB with an explicit truncation marker.
"""

from __future__ import annotations

import re

DISPLAY_LIMIT_BYTES = 4096
TRUNCATION_MARKER = "\n…[truncated]"
INVALID_MODEL_ID = "[invalid model id]"

# ANSI CSI/OSC sequences and other escapes.
_ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")
# C0 controls except \n (line feed preserved); tab and others removed.
_C0_C1_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\x80-\x9f]")

# Known credential forms, redacted before display.
_CREDENTIAL_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
    re.compile(r"(?i)api[_-]?key[=:]\s*\S+"),
    re.compile(r"(?i)authorization[=:]\s*\S+"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
]
_REDACTED = "[redacted]"


def sanitize_for_display(raw: bytes | str) -> str:
    """The full R2 pipeline. Output is always at most 4 KiB."""
    data = raw.encode("utf-8", errors="replace") if isinstance(raw, str) else raw
    text = data.decode("utf-8", errors="replace")
    text = _ANSI_RE.sub("", text)
    text = _C0_C1_RE.sub("", text)
    for pattern in _CREDENTIAL_PATTERNS:
        text = pattern.sub(_REDACTED, text)
    encoded = text.encode("utf-8")
    if len(encoded) > DISPLAY_LIMIT_BYTES:
        cut = encoded[:DISPLAY_LIMIT_BYTES]
        # do not split a multibyte character
        while True:
            try:
                text = cut.decode("utf-8")
                break
            except UnicodeDecodeError:
                cut = cut[:-1]
        return text + TRUNCATION_MARKER
    return text


def sanitize_model_id(value: str) -> str:
    """Model ids displayed as diagnostics are separately validated and
    bounded; untrusted invalid ids are rendered as ``[invalid model id]``."""
    from testudo.seats.validation import ValidationError, validate_model_id

    try:
        validate_model_id("model-id", value)
    except ValidationError:
        return INVALID_MODEL_ID
    return value
