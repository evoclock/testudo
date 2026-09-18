# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""C1 field-validation classes (spec section 3.2).

All string input is valid UTF-8 and rejects NUL, C0/C1 controls, DEL, and
unpaired surrogates before field-specific validation. Validation errors
identify the field and the class and never normalize invalid input except
hostname case and canonical IP form.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from typing import Final

# --- common string rules -----------------------------------------------------

_CONTROL_RE: Final = re.compile(r"[\x00-\x1f\x7f\x80-\x9f]")


class ValidationError(ValueError):
    """A field failed validation; ``field`` and ``error_class`` are stable ids."""

    def __init__(self, field: str, error_class: str, detail: str = "") -> None:
        self.field = field
        self.error_class = error_class
        message = f"invalid {field}: {error_class}"
        if detail:
            message = f"{message} ({detail})"
        super().__init__(message)


def _check_common(field: str, value: str) -> None:
    if not isinstance(value, str):
        raise ValidationError(field, "type", "expected a string")
    # NUL, C0/C1 controls, DEL.
    if _CONTROL_RE.search(value):
        raise ValidationError(field, "control-character")
    # Unpaired surrogates cannot survive UTF-8 round-trip; Python strings can
    # carry them, so reject explicitly.
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValidationError(field, "encoding", str(exc)) from exc


def _first_char_not_dash(field: str, value: str) -> None:
    if value.startswith("-"):
        raise ValidationError(field, "leading-dash")


# --- field classes -----------------------------------------------------------

_UUID4_RE: Final = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_LABEL_RE: Final = re.compile(r"^[\x20-\x7e]+$")
_UNIT_RE: Final = re.compile(r"^[A-Za-z0-9_.@-]+$")
_MODEL_ID_RE: Final = re.compile(r"^[A-Za-z0-9._/:+-]+$")
_ABS_PATH_RE: Final = re.compile(r"^/[A-Za-z0-9_./+@-]*$")
_SUBCOMMAND_RE: Final = re.compile(r"^[A-Za-z0-9_.-]+$")
_SSH_USER_RE: Final = re.compile(r"^[a-z_][a-z0-9_.-]*$")
_HOSTNAME_RE: Final = re.compile(
    r"^(?=.{1,253}\.?$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.?$"
)
_HEX64_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_HEX32_RE: Final = re.compile(r"^[0-9a-f]{32}$")
_LOCK_BASENAME_RE: Final = re.compile(r"^endpoint-[0-9a-f]{64}\.lock$")
_BOOT_ID_RE: Final = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_FINGERPRINT_RE: Final = re.compile(r"^SHA256:[A-Za-z2-7+/]{43}$")
_OPTION_TOKEN_RE: Final = re.compile(r"^--[a-z][a-z0-9-]*$|^-[A-Za-z0-9]$")
_ARGUMENT_VALUE_RE: Final = re.compile(r"^[A-Za-z0-9._/:+=,@%-]+$")
_RFC3339_UTC_RE: Final = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")


def validate_uuid4(field: str, value: str) -> str:
    _check_common(field, value)
    if not _UUID4_RE.match(value):
        raise ValidationError(field, "uuid4")
    return value


def new_uuid4() -> str:
    """Bridge-generated UUIDv4 with 122 random bits, canonical lowercase."""
    return str(uuid.uuid4())


def validate_label(field: str, value: str) -> str:
    _check_common(field, value)
    if not 1 <= len(value) <= 128 or not _LABEL_RE.match(value):
        raise ValidationError(field, "label")
    return value


def validate_unit(field: str, value: str) -> str:
    _check_common(field, value)
    if not 1 <= len(value) <= 255 or not _UNIT_RE.match(value):
        raise ValidationError(field, "unit")
    _first_char_not_dash(field, value)
    return value


def validate_model_id(field: str, value: str) -> str:
    _check_common(field, value)
    if not 1 <= len(value) <= 512 or not _MODEL_ID_RE.match(value):
        raise ValidationError(field, "model-id")
    _first_char_not_dash(field, value)
    return value


def validate_absolute_path(field: str, value: str) -> str:
    _check_common(field, value)
    if not 1 <= len(value) <= 1024 or not _ABS_PATH_RE.match(value):
        raise ValidationError(field, "absolute-path")
    if value.endswith("/") and value != "/":
        raise ValidationError(field, "absolute-path", "trailing slash")
    components = value.split("/")[1:]
    if value != "/" and any(component in {"", ".", ".."} for component in components):
        raise ValidationError(field, "absolute-path", "empty/dot component")
    return value


def validate_subcommand(field: str, value: str) -> str:
    _check_common(field, value)
    if not 1 <= len(value) <= 64 or not _SUBCOMMAND_RE.match(value):
        raise ValidationError(field, "subcommand")
    _first_char_not_dash(field, value)
    return value


def validate_ssh_alias(field: str, value: str) -> str:
    """RFC1123 hostname syntax without wildcard/negation, or a single DNS label."""
    _check_common(field, value)
    if not 1 <= len(value) <= 255:
        raise ValidationError(field, "ssh-alias")
    _first_char_not_dash(field, value)
    if any(character in value for character in "*!?"):
        raise ValidationError(field, "ssh-alias", "wildcard/negation character")
    lowered = value.lower()
    if not _HOSTNAME_RE.match(lowered):
        raise ValidationError(field, "ssh-alias")
    return value


def validate_ssh_user(field: str, value: str) -> str:
    _check_common(field, value)
    if not 1 <= len(value) <= 32 or not _SSH_USER_RE.match(value):
        raise ValidationError(field, "ssh-user")
    return value


def canonical_hostname(field: str, value: str) -> str:
    """RFC1123 hostname (lowercased, no trailing dot) or literal IP (RFC5952)."""
    _check_common(field, value)
    if not 1 <= len(value) <= 253:
        raise ValidationError(field, "hostname")
    # Literal IP: canonicalize (IPv6 to RFC5952 compressed lowercase form).
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        pass
    lowered = value.lower()
    if lowered.endswith("."):
        lowered = lowered[:-1]
    if not _HOSTNAME_RE.match(lowered):
        raise ValidationError(field, "hostname")
    return lowered


def validate_port(field: str, value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(field, "type", "expected a JSON integer")
    if not 1 <= value <= 65535:
        raise ValidationError(field, "port")
    return value


def validate_timeout(field: str, value: int, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(field, "type", "expected a JSON integer")
    if not minimum <= value <= maximum:
        raise ValidationError(field, "timeout")
    return value


def validate_option_token(field: str, value: str) -> str:
    _check_common(field, value)
    if not _OPTION_TOKEN_RE.match(value) or len(value) > 64:
        raise ValidationError(field, "option-token")
    return value


def validate_argument_value(field: str, value: str) -> str:
    _check_common(field, value)
    if not 1 <= len(value) <= 1024:
        raise ValidationError(field, "argument-value")
    _first_char_not_dash(field, value)
    if not _ARGUMENT_VALUE_RE.match(value):
        raise ValidationError(field, "argument-value")
    return value


def validate_launch_argv(field: str, argv: list[str]) -> list[str]:
    """Template C ``launch_argv``: 1-128 strings; element 0 is an absolute
    path; each later element must match exactly one of option-token or
    argument-value (a token matching both or neither is rejected)."""
    if not isinstance(argv, list) or not 1 <= len(argv) <= 128:
        raise ValidationError(field, "launch-argv", "length out of range 1-128")
    validate_absolute_path(f"{field}[0]", argv[0])
    for index, element in enumerate(argv[1:], start=1):
        _check_common(f"{field}[{index}]", element)
        is_option = bool(_OPTION_TOKEN_RE.match(element)) and len(element) <= 64
        is_argument = (
            bool(_ARGUMENT_VALUE_RE.match(element))
            and 1 <= len(element) <= 1024
            and not element.startswith("-")
        )
        if is_option == is_argument:
            raise ValidationError(
                field, "launch-argv", f"element {index} ambiguous or invalid: {element!r}"
            )
    return argv


def validate_hex64(field: str, value: str) -> str:
    _check_common(field, value)
    if not _HEX64_RE.match(value):
        raise ValidationError(field, "hex64")
    return value


def validate_nonce(field: str, value: str) -> str:
    _check_common(field, value)
    if not _HEX32_RE.match(value):
        raise ValidationError(field, "nonce")
    return value


def validate_lock_basename(field: str, value: str) -> str:
    _check_common(field, value)
    if not _LOCK_BASENAME_RE.match(value):
        raise ValidationError(field, "lock-basename")
    return value


def validate_boot_id(field: str, value: str) -> str:
    """Canonical lowercase UUID of any version (Linux boot_id)."""
    _check_common(field, value)
    if not _BOOT_ID_RE.match(value):
        raise ValidationError(field, "boot-id")
    return value


def validate_fingerprint(field: str, value: str) -> str:
    """``SHA256:`` plus 43 base64 characters (no padding in OpenSSH form)."""
    _check_common(field, value)
    if not _FINGERPRINT_RE.match(value):
        raise ValidationError(field, "fingerprint")
    return value


def validate_rfc3339_utc(field: str, value: str) -> str:
    _check_common(field, value)
    if not _RFC3339_UTC_RE.match(value):
        raise ValidationError(field, "rfc3339")
    return value


def validate_seat_template(field: str, value: str) -> str:
    if value not in {"systemd-user", "control-script", "bare-command"}:
        raise ValidationError(field, "template")
    return value


def validate_transport_kind(field: str, value: str) -> str:
    if value not in {"trusted-lan", "https", "ssh-tunnel"}:
        raise ValidationError(field, "transport")
    return value


def validate_ssh_kind(field: str, value: str) -> str:
    if value not in {"alias", "explicit"}:
        raise ValidationError(field, "ssh-kind")
    return value
