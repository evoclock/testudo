# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-only

"""Newline-framed process boundary for Testudo contained assignments.

Every command on this boundary is authenticated with a per-session command
credential before it is applied. The verifier is bound to the session and to
one nonce per command, so a captured frame cannot be replayed on another
session and any operation - start, observe, cancel, receipt, or reconcile -
arriving without a valid, fresh, session-bound credential fails closed.
Nonces are never evicted: history is retained for the whole authenticated
session and the session must be terminated and rotated before the bounded
command budget is exhausted, so no reuse is ever permitted.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, TextIO

from pydantic import BaseModel, ConfigDict, Field

from testudo.runtime.assignment import AssignmentError, AssignmentService

PROTOCOL_SCHEMA = "testudo.assignment.protocol.v1"
MAX_MESSAGE_BYTES = 128 * 1024
# Bounded per-session command budget. History is never evicted; a session that
# reaches the budget must be terminated and rotated with a fresh verifier and
# secret before any further command is applied.
_MAX_SESSION_COMMANDS = 1024


_SESSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


@dataclass(frozen=True, slots=True)
class SessionSecret:
    """One trusted, dispatcher-provisioned session credential.

    The dispatcher owns session identity and mints exactly one secret per
    framed session through :func:`provision_session_secret`. The provisioning
    digest binds the session identity to the secret so both endpoints can
    verify they hold the same session without ever transmitting the secret
    itself over the framed boundary.
    """

    session_id: str
    secret: bytes
    provisioning_sha256: str


def provision_session_secret(session_id: str) -> SessionSecret:
    """Provision one trusted session secret bound to one session identity.

    This is the only minting path: the dispatcher calls it once per session
    and hands the secret to the framed transport peer out-of-band. The server
    verifier never mints; it only consumes an explicitly provisioned secret.
    Exactly one secret is active for one session identity at a time: minting
    a fresh secret for the same session identity revokes every earlier
    generation, and a verifier built from a revoked secret fails closed.
    """
    if not isinstance(session_id, str) or _SESSION_ID.fullmatch(session_id) is None:
        raise AssignmentError("session id must be 1-128 safe identifier characters")
    secret = secrets.token_bytes(32)
    binding = hmac.new(secret, f"session:{session_id}".encode(), hashlib.sha256).hexdigest()
    provisioned = SessionSecret(session_id=session_id, secret=secret, provisioning_sha256=binding)
    with _SECRET_REGISTRY_LOCK:
        _ACTIVE_GENERATIONS[session_id] = binding
    return provisioned


# Process-local transport registry. It retains only provisioning digests, never
# secret bytes. All access is serialized because framed sessions may be served
# concurrently. Removing or replacing an entry immediately invalidates every
# verifier for the prior generation on its next command.
_ACTIVE_GENERATIONS: dict[str, str] = {}
_SECRET_REGISTRY_LOCK = threading.RLock()


def revoke_session_secret(session_id: str) -> None:
    """Revoke the active secret for one session identity.

    A revoked session cannot be re-entered with its old secret: the next
    verifier built from it fails closed. The next mint for the same identity
    starts a fresh generation.
    """
    if not isinstance(session_id, str) or _SESSION_ID.fullmatch(session_id) is None:
        raise AssignmentError("session id must be 1-128 safe identifier characters")
    with _SECRET_REGISTRY_LOCK:
        _ACTIVE_GENERATIONS.pop(session_id, None)


def command_credential(secret: bytes, nonce: str, request_id: str, *, session_id: str = "") -> str:
    """Return the HMAC credential binding one command to one session nonce.

    When a session identity is supplied it is folded into the MAC input, so a
    credential minted for one session can never verify on another session
    even if both sessions share a secret.
    """
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise AssignmentError("command credential secret must be at least 32 bytes")
    if not isinstance(nonce, str) or not nonce or len(nonce) > 128:
        raise AssignmentError("command credential nonce is required")
    if not isinstance(request_id, str) or not request_id or len(request_id) > 128:
        raise AssignmentError("command credential request_id is required")
    if not isinstance(session_id, str) or len(session_id) > 128:
        raise AssignmentError("command credential session_id is invalid")
    message = f"{nonce}:{request_id}" if not session_id else f"{session_id}:{nonce}:{request_id}"
    return hmac.new(secret, message.encode(), hashlib.sha256).hexdigest()


class CommandSessionVerifier:
    """Session-bound verifier for framed assignment commands.

    One verifier serves exactly one framed session and is constructed only
    from an explicitly provisioned :class:`SessionSecret`; it never mints a
    secret itself. Each command must carry ``credential`` plus ``nonce``; the
    credential is the session secret's HMAC over ``(session_id, nonce,
    request_id)``, so a captured frame cannot be replayed on this session or
    any other session. Nonces form a canonical integer sequence: a nonce is a
    base-ten non-negative integer without redundant leading zeros, ordering is
    numeric, every nonce is accepted at most once, and the sequence must be
    strictly increasing within the session. The full history is retained for
    the lifetime of the session - nothing is ever evicted and no reuse is
    ever permitted. A session that exhausts its bounded command budget fails
    closed until it is terminated and rotated with a freshly provisioned
    secret.
    """

    def __init__(self, provisioned: SessionSecret) -> None:
        if not isinstance(provisioned, SessionSecret):
            raise AssignmentError("a provisioned session secret is required")
        if not isinstance(provisioned.secret, bytes) or len(provisioned.secret) < 32:
            raise AssignmentError("command credential secret must be at least 32 bytes")
        expected = hmac.new(
            provisioned.secret,
            f"session:{provisioned.session_id}".encode(),
            hashlib.sha256,
        ).hexdigest()
        if provisioned.provisioning_sha256 != expected:
            raise AssignmentError("session secret provisioning digest does not match")
        with _SECRET_REGISTRY_LOCK:
            active = _ACTIVE_GENERATIONS.get(provisioned.session_id)
        if active != provisioned.provisioning_sha256:
            raise AssignmentError("session secret generation is not active")
        self._secret = provisioned.secret
        self._session_id = provisioned.session_id
        self._provisioning = provisioned.provisioning_sha256
        self._seen: set[int] = set()
        self._high_water: int | None = None
        self._lock = threading.Lock()

    @property
    def session_id(self) -> str:
        """Return the session identity this verifier is bound to."""
        return self._session_id

    @property
    def provisioning_sha256(self) -> str:
        """Return the digest binding the session identity to the secret."""
        return self._provisioning

    def handshake(self) -> dict[str, object]:
        """Return the session identity and provisioning digest for binding.

        The dispatcher compares this against its own provisioned secret's
        digest before trusting any command response from the framed peer.
        """
        return {
            "schema": "testudo.assignment.session.v1",
            "session_id": self._session_id,
            "provisioning_sha256": self._provisioning,
        }

    @property
    def commands_remaining(self) -> int:
        """Return the bounded command budget left before session rotation."""
        with self._lock:
            return max(0, _MAX_SESSION_COMMANDS - len(self._seen))

    def verify(self, value: Mapping[str, Any]) -> None:
        """Verify one command's credential or fail closed."""
        nonce = value.get("nonce")
        request_id = value.get("request_id")
        credential = value.get("credential")
        if not isinstance(nonce, str) or not nonce or len(nonce) > 128:
            raise AssignmentError("assignment command nonce is required")
        if not isinstance(request_id, str) or not request_id or len(request_id) > 128:
            raise AssignmentError("assignment command request_id is required")
        if not isinstance(credential, str) or not credential:
            raise AssignmentError("assignment command credential is required")
        expected = command_credential(self._secret, nonce, request_id, session_id=self._session_id)
        if not hmac.compare_digest(credential, expected):
            raise AssignmentError("assignment command credential verification failed")
        with self._lock:
            with _SECRET_REGISTRY_LOCK:
                active = _ACTIVE_GENERATIONS.get(self._session_id)
            if active != self._provisioning:
                raise AssignmentError("assignment session secret is revoked or rotated")
            # Canonical integer sequence: the nonce must be a base-ten
            # non-negative integer without a sign, fraction, whitespace, or
            # redundant leading zeros. Ordering is numeric, so 10 follows 9
            # regardless of string sort order.
            if not nonce.isascii() or not nonce.isdecimal() or (len(nonce) > 1 and nonce[0] == "0"):
                raise AssignmentError(
                    "assignment command nonce must be a canonical base-ten integer"
                )
            sequence = int(nonce)
            if sequence in self._seen:
                raise AssignmentError("assignment command nonce was already used")
            if len(self._seen) >= _MAX_SESSION_COMMANDS:
                raise AssignmentError(
                    "assignment session command budget is exhausted; "
                    "terminate and rotate the session before continuing"
                )
            if self._high_water is not None and sequence <= self._high_water:
                raise AssignmentError(
                    "assignment command nonce must be strictly monotonic within the session"
                )
            self._seen.add(sequence)
            self._high_water = sequence

class AssignmentCommand(BaseModel):
    """One closed process-boundary command."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    schema_: str = Field(PROTOCOL_SCHEMA, alias="schema")
    request_id: str = Field(min_length=1, max_length=128)
    operation: str
    nonce: str = Field(min_length=1, max_length=128)
    credential: str = Field(min_length=1, max_length=128)
    assignment_id: str | None = None
    envelope_id: str | None = None
    reason: str | None = None
    status: Literal["failed", "cancelled"] | None = None
    assignment: dict[str, Any] | None = None


def handle_command(
    service: AssignmentService,
    value: Mapping[str, Any],
    *,
    verifier: CommandSessionVerifier | None = None,
) -> dict[str, object]:
    """Apply one authenticated protocol command and return one response.

    ``verifier`` must be supplied; without it every command fails closed, so
    the operation router can never be reached on an unauthenticated session.
    """
    if verifier is None:
        raise AssignmentError("assignment command credential verifier is required")
    verifier.verify(value)
    command = AssignmentCommand.model_validate(value)
    if command.schema_ != PROTOCOL_SCHEMA:
        raise AssignmentError("unsupported assignment protocol schema")
    operation = command.operation
    result: object
    if operation == "start":
        if command.assignment is None or any(
            value is not None
            for value in (command.assignment_id, command.envelope_id, command.reason, command.status)
        ):
            raise AssignmentError("start requires only assignment")
        result = service.start(command.assignment).model_dump(mode="json", by_alias=True)
    elif operation == "observe":
        _require_only(command, "assignment_id")
        result = [
            event.model_dump(mode="json", by_alias=True)
            for event in service.observe(command.assignment_id or "")
        ]
    elif operation == "cancel":
        if not command.assignment_id or not command.reason:
            raise AssignmentError("cancel requires assignment_id and reason")
        if command.assignment is not None or command.envelope_id is not None:
            raise AssignmentError("cancel contains unsupported fields")
        result = service.cancel(command.assignment_id, command.reason).model_dump(
            mode="json", by_alias=True
        )
    elif operation == "receipt":
        _require_only(command, "assignment_id")
        receipt = service.receipt(command.assignment_id or "")
        result = None if receipt is None else receipt.model_dump(mode="json", by_alias=True)
    elif operation == "terminalize":
        if command.envelope_id is not None or command.assignment is not None:
            raise AssignmentError("terminalize contains unsupported fields")
        if not command.assignment_id:
            raise AssignmentError("terminalize requires assignment_id")
        if not command.reason:
            raise AssignmentError("terminalize requires reason")
        if command.status is None:
            raise AssignmentError("terminalize requires status")
        result = service.terminalize(
            command.assignment_id,
            status=command.status,
            reason=command.reason,
        ).model_dump(mode="json", by_alias=True)
    elif operation == "reconcile":
        _require_only(command, "envelope_id")
        result = dict(service.reconcile(command.envelope_id or ""))
    else:
        raise AssignmentError("unsupported assignment operation")
    return {
        "schema": PROTOCOL_SCHEMA,
        "request_id": command.request_id,
        "ok": True,
        "result": result,
    }


def _require_only(command: AssignmentCommand, field: str) -> None:
    values = {
        "assignment_id": command.assignment_id,
        "envelope_id": command.envelope_id,
        "reason": command.reason,
        "status": command.status,
        "assignment": command.assignment,
    }
    if not values[field] or any(
        value is not None for name, value in values.items() if name != field
    ):
        raise AssignmentError(f"{command.operation} requires only {field}")


def serve_framed(
    service: AssignmentService,
    input_stream: Iterable[str],
    output_stream: TextIO,
    *,
    verifier: CommandSessionVerifier | None = None,
) -> None:
    """Serve finite newline-delimited JSON commands without retry or fallback.

    ``verifier`` must be supplied for a real session; without it every command
    is refused, so an unauthenticated boundary can never read or mutate state.

    Per-frame state is initialized before any parsing, so a malformed first or
    later frame always yields one correlated error response and the session
    loop survives; a stale assignment or envelope identity is likewise refused
    with a correlated error instead of tearing down the session.
    """
    for line in input_stream:
        # Per-frame state is initialized safely: an unparseable frame has no
        # request id and never reaches the operation router.
        request_id: str | None = None
        if len(line.encode("utf-8")) > MAX_MESSAGE_BYTES:
            response = _error_response(None, "assignment message exceeds the transport limit")
        else:
            try:
                parsed = json.loads(line)
                if not isinstance(parsed, Mapping):
                    raise AssignmentError("assignment command must be a JSON object")
                candidate = parsed.get("request_id")
                if isinstance(candidate, str) and candidate:
                    request_id = candidate
                if verifier is None:
                    raise AssignmentError(
                        "assignment session requires a command credential verifier"
                    )
                response = handle_command(service, parsed, verifier=verifier)
            except Exception as exc:
                response = _error_response(request_id, f"{type(exc).__name__}: {exc}")
        output_stream.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
        output_stream.flush()


def _error_response(request_id: str | None, error: str) -> dict[str, object]:
    return {
        "schema": PROTOCOL_SCHEMA,
        "request_id": request_id,
        "ok": False,
        "error": error[:4096],
    }


__all__ = [
    "MAX_MESSAGE_BYTES",
    "PROTOCOL_SCHEMA",
    "AssignmentCommand",
    "CommandSessionVerifier",
    "SessionSecret",
    "command_credential",
    "handle_command",
    "provision_session_secret",
    "revoke_session_secret",
    "serve_framed",
]
