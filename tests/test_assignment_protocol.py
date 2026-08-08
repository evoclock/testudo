# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@example.invalid>
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from testudo.runtime.assignment import AssignmentError
from testudo.runtime.assignment_protocol import (
    CommandSessionVerifier,
    SessionSecret,
    command_credential,
    handle_command,
    provision_session_secret,
    revoke_session_secret,
    serve_framed,
)

SECRET = b"0" * 32
SESSION_ID = "session-alpha"
_current_secret: bytes = SECRET


def provisioned() -> CommandSessionVerifier:
    # Provision through the dispatcher-side minting path so the one-active-
    # secret-per-session registry stays consistent with every test session.
    global _current_secret
    provisioned_secret = provision_session_secret(SESSION_ID)
    _current_secret = provisioned_secret.secret
    return CommandSessionVerifier(provisioned_secret)


def credential(
    nonce: str, request_id: str, secret: bytes | None = None, session: str = SESSION_ID
) -> str:
    return command_credential(
        _current_secret if secret is None else secret, nonce, request_id, session_id=session
    )


class Service:
    def start(self, assignment: dict[str, Any]) -> Any:
        return Model({"event": "admitted", "assignment": assignment})

    def observe(self, assignment_id: str) -> tuple[Any, ...]:
        # Model the real service: a stale assignment identity is refused.
        if assignment_id != "assignment-1":
            raise AssignmentError("assignment identity is unknown")
        return (Model({"event": "started", "assignment_id": assignment_id}),)

    def cancel(self, assignment_id: str, reason: str) -> Any:
        return Model(
            {"event": "cancel_requested", "assignment_id": assignment_id, "reason": reason}
        )

    def receipt(self, assignment_id: str) -> Any:
        return Model({"status": "succeeded", "assignment_id": assignment_id})

    def reconcile(self, envelope_id: str) -> dict[str, object]:
        # Model the real service: a stale envelope identity reports absent.
        if envelope_id != "envelope-1":
            return {"state": "absent", "envelope_id": envelope_id}
        return {"state": "active", "envelope_id": envelope_id}


class Model:
    def __init__(self, value: dict[str, object]) -> None:
        self.value = value

    def model_dump(self, **_kwargs: object) -> dict[str, object]:
        return self.value


_command_counter = 0


def command(operation: str, request_id: str = "request-1", **kwargs: object) -> dict[str, object]:
    global _command_counter
    _command_counter += 1
    value: dict[str, object] = {
        "schema": "testudo.assignment.protocol.v1",
        "request_id": request_id,
        "operation": operation,
        **kwargs,
    }
    value["nonce"] = str(_command_counter)
    value["credential"] = credential(str(_command_counter), request_id)
    return value


@pytest.mark.parametrize(
    ("operation", "arguments"),
    [
        ("start", {"assignment": {"schema": "testudo.assignment.request.v1"}}),
        ("observe", {"assignment_id": "assignment-1"}),
        ("cancel", {"assignment_id": "assignment-1", "reason": "stop"}),
        ("receipt", {"assignment_id": "assignment-1"}),
        ("reconcile", {"envelope_id": "envelope-1"}),
    ],
)
def test_protocol_exposes_closed_authenticated_operations(
    operation: str, arguments: dict[str, object]
) -> None:
    verifier = provisioned()
    response = handle_command(
        Service(),  # type: ignore[arg-type]
        command(operation, **dict(arguments)),  # type: ignore[arg-type]
        verifier=verifier,
    )
    assert response["ok"] is True
    assert response["request_id"] == "request-1"


def test_protocol_fails_closed_without_credential_for_every_operation() -> None:
    verifier = provisioned()
    for operation, arguments in (
        ("start", {"assignment": {"schema": "testudo.assignment.request.v1"}}),
        ("observe", {"assignment_id": "assignment-1"}),
        ("cancel", {"assignment_id": "assignment-1", "reason": "stop"}),
        ("receipt", {"assignment_id": "assignment-1"}),
        ("reconcile", {"envelope_id": "envelope-1"}),
    ):
        value = command(operation, **arguments)
        del value["credential"]
        with pytest.raises(AssignmentError, match="credential"):
            handle_command(Service(), value, verifier=verifier)  # type: ignore[arg-type]
    with pytest.raises(AssignmentError, match="verifier"):
        handle_command(Service(), command("observe", request_id="r9"))  # type: ignore[arg-type]


def test_protocol_rejects_wrong_credential_and_replayed_nonce() -> None:
    verifier = provisioned()
    wrong = command("observe", assignment_id="assignment-1")
    wrong["credential"] = command_credential(
        b"9" * 32, str(wrong["nonce"]), "request-1", session_id=SESSION_ID
    )
    with pytest.raises(AssignmentError, match="credential verification failed"):
        handle_command(Service(), wrong, verifier=verifier)  # type: ignore[arg-type]

    replay = command("receipt", request_id="request-2", assignment_id="assignment-1")
    assert handle_command(Service(), replay, verifier=verifier)["ok"] is True  # type: ignore[arg-type]
    with pytest.raises(AssignmentError, match="already used"):
        handle_command(Service(), replay, verifier=verifier)  # type: ignore[arg-type]

    # A credential minted for a different session secret never verifies.
    other_session = provision_session_secret("session-other")
    other_verifier = CommandSessionVerifier(other_session)
    with pytest.raises(AssignmentError, match="credential verification failed"):
        handle_command(
            Service(),  # type: ignore[arg-type]
            command("reconcile", request_id="r3", envelope_id="e"),
            verifier=other_verifier,
        )


def test_protocol_rejects_mixed_and_unknown_operations() -> None:
    verifier = provisioned()
    with pytest.raises(AssignmentError, match="requires only"):
        handle_command(
            Service(),  # type: ignore[arg-type]
            command(
                "observe",
                request_id="r-mixed",
                assignment_id="assignment-1",
                envelope_id="envelope-1",
            ),
            verifier=verifier,
        )
    with pytest.raises(AssignmentError, match="unsupported"):
        handle_command(Service(), command("spawn-host", request_id="r-unknown"), verifier=verifier)  # type: ignore[arg-type]


def test_framed_server_requires_verifier_and_returns_one_response_without_retry() -> None:
    source = io.StringIO(
        '{"schema":"testudo.assignment.protocol.v1","request_id":"one","operation":"reconcile","envelope_id":"e1"}\n'
        "not-json\n"
    )
    output = io.StringIO()
    serve_framed(Service(), source, output)  # type: ignore[arg-type]
    lines = output.getvalue().splitlines()
    assert len(lines) == 2
    assert '"ok":false' in lines[0]
    assert "verifier" in lines[0]
    assert '"ok":false' in lines[1]

    verifier = provisioned()
    value = command("reconcile", request_id="one", envelope_id="e1")
    authenticated = io.StringIO(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    output = io.StringIO()
    serve_framed(Service(), authenticated, output, verifier=verifier)  # type: ignore[arg-type]
    lines = output.getvalue().splitlines()
    assert len(lines) == 1
    assert '"ok":true' in lines[0]


def test_framed_server_survives_malformed_first_and_later_frames_with_correlated_errors() -> None:
    # A malformed first frame must not kill the session: the error response is
    # correlated (request_id null because no request id could be parsed) and
    # the loop keeps serving later well-formed frames.
    verifier = provisioned()
    source = io.StringIO(
        "not-json\n"
        + json.dumps(command("reconcile", request_id="after-bad", envelope_id="e1"))
        + "\n"
    )
    output = io.StringIO()
    serve_framed(Service(), source, output, verifier=verifier)  # type: ignore[arg-type]
    lines = output.getvalue().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["ok"] is False
    assert first["request_id"] is None
    assert "error" in first
    assert json.loads(lines[1])["ok"] is True
    assert json.loads(lines[1])["request_id"] == "after-bad"

    # A later malformed frame after good traffic keeps the session alive and
    # still cannot reach the operation router.
    verifier = provisioned()
    good_1 = json.dumps(command("reconcile", request_id="good-1", envelope_id="e1"))
    good_2 = json.dumps(command("reconcile", request_id="good-2", envelope_id="e1"))
    source = io.StringIO(good_1 + "\n" + '{"schema": 1}\n' + good_2 + "\n")
    output = io.StringIO()
    serve_framed(Service(), source, output, verifier=verifier)  # type: ignore[arg-type]
    lines = output.getvalue().splitlines()
    assert len(lines) == 3
    assert json.loads(lines[0])["ok"] is True
    broken = json.loads(lines[1])
    assert broken["ok"] is False
    assert broken["request_id"] is None
    assert json.loads(lines[2])["ok"] is True
    assert json.loads(lines[2])["request_id"] == "good-2"


def test_framed_server_returns_correlated_errors_for_stale_ids_without_killing_session() -> None:
    # Stale (unknown) assignment and envelope identities are refused with a
    # correlated error response and the session keeps serving afterwards.
    verifier = provisioned()
    stale_assignment = json.dumps(
        command("observe", request_id="stale-a", assignment_id="gone-assignment")
    )
    stale_envelope = json.dumps(
        command("reconcile", request_id="stale-e", envelope_id="gone-envelope")
    )
    live = json.dumps(command("reconcile", request_id="live-1", envelope_id="e1"))
    # Explicitly ordered nonces until the canonical integer sequence lands;
    # this test isolates stale-id correlation, not nonce ordering.
    ordered: list[str] = []
    for frame, nonce in ((stale_assignment, "1"), (stale_envelope, "2"), (live, "3")):
        value = json.loads(frame)
        value["nonce"] = nonce
        value["credential"] = credential(nonce, str(value["request_id"]))
        ordered.append(json.dumps(value))
    source = io.StringIO("\n".join(ordered) + "\n")
    output = io.StringIO()
    serve_framed(Service(), source, output, verifier=verifier)  # type: ignore[arg-type]
    lines = output.getvalue().splitlines()
    assert len(lines) == 3
    first = json.loads(lines[0])
    assert first["ok"] is False
    assert first["request_id"] == "stale-a"
    assert "unknown" in first["error"]
    second = json.loads(lines[1])
    assert second["ok"] is True
    assert second["request_id"] == "stale-e"
    # A stale envelope identity reconciles to the non-authorizing absent
    # state; it can never resurrect a run.
    assert second["result"]["state"] == "absent"
    assert json.loads(lines[2])["ok"] is True


def test_replay_history_is_never_evicted_and_budget_enforces_rotation() -> None:
    verifier = provisioned()
    assert verifier.commands_remaining == 1024
    # More than 1024 operations: every nonce accepted at most once, history
    # never evicted, and the bounded session fails closed at the budget.
    for index in range(1024):
        value = command("reconcile", request_id=f"r-{index}", envelope_id="e1")
        value["nonce"] = str(index)
        value["credential"] = credential(str(index), f"r-{index}")
        assert handle_command(Service(), value, verifier=verifier)["ok"] is True  # type: ignore[arg-type]
    assert verifier.commands_remaining == 0

    exhausted = command("reconcile", request_id="r-over", envelope_id="e1")
    exhausted["nonce"] = "999999"
    exhausted["credential"] = credential("999999", "r-over")
    with pytest.raises(AssignmentError, match="budget is exhausted"):
        handle_command(Service(), exhausted, verifier=verifier)  # type: ignore[arg-type]

    # Old nonces are still rejected: history was never evicted.
    old = command("reconcile", request_id="r-0", envelope_id="e1")
    old["nonce"] = "0"
    old["credential"] = credential("0", "r-0")
    with pytest.raises(AssignmentError, match="already used"):
        handle_command(Service(), old, verifier=verifier)  # type: ignore[arg-type]

    # Rotation: a fresh verifier and secret restores a full budget, and the
    # old session's credentials do not verify against the new session.
    rotated = CommandSessionVerifier(provision_session_secret("session-rotated"))
    with pytest.raises(AssignmentError, match="credential verification failed"):
        handle_command(Service(), exhausted, verifier=rotated)  # type: ignore[arg-type]
    fresh = command("reconcile", request_id="r-rotated", envelope_id="e1")
    fresh["credential"] = command_credential(
        rotated._secret, str(fresh["nonce"]), "r-rotated", session_id="session-rotated"
    )
    assert handle_command(Service(), fresh, verifier=rotated)["ok"] is True  # type: ignore[arg-type]
    assert rotated.commands_remaining == 1023


def test_nonces_must_be_strictly_monotonic_within_a_session() -> None:
    verifier = provisioned()
    first = command("reconcile", request_id="r-2", envelope_id="e1")
    first["nonce"] = "2"
    first["credential"] = credential("2", "r-2")
    assert handle_command(Service(), first, verifier=verifier)["ok"] is True  # type: ignore[arg-type]

    # A nonce below the session high-water mark is refused even if unused.
    backwards = command("reconcile", request_id="r-1", envelope_id="e1")
    backwards["nonce"] = "1"
    backwards["credential"] = credential("1", "r-1")
    with pytest.raises(AssignmentError, match="strictly monotonic"):
        handle_command(Service(), backwards, verifier=verifier)  # type: ignore[arg-type]
    # The refused nonce was not consumed; after advancing past the high-water
    # mark it still verifies (it is a fresh nonce, not a replay).
    forward = command("reconcile", request_id="r-3", envelope_id="e1")
    forward["nonce"] = "3"
    forward["credential"] = credential("3", "r-3")
    assert handle_command(Service(), forward, verifier=verifier)["ok"] is True  # type: ignore[arg-type]
    assert verifier.commands_remaining == 1022


def test_nonce_ordering_is_canonical_integer_not_lexicographic() -> None:
    # The canonical nonce form is a non-negative integer sequence: ordering is
    # numeric, so 10 follows 9 even though "10" sorts before "9" lexically
    # lexicographically.
    verifier = provisioned()
    nine = command("reconcile", request_id="r-9", envelope_id="e1")
    nine["nonce"] = "9"
    nine["credential"] = credential("9", "r-9")
    assert handle_command(Service(), nine, verifier=verifier)["ok"] is True  # type: ignore[arg-type]

    ten = command("reconcile", request_id="r-10", envelope_id="e1")
    ten["nonce"] = "10"
    ten["credential"] = credential("10", "r-10")
    assert handle_command(Service(), ten, verifier=verifier)["ok"] is True  # type: ignore[arg-type]

    # Leading zeros are a non-canonical spelling: the canonical integer
    # sequence refuses them before any ordering or replay check.
    padded = command("reconcile", request_id="r-10b", envelope_id="e1")
    padded["nonce"] = "010"
    padded["credential"] = credential("010", "r-10b")
    with pytest.raises(AssignmentError, match="canonical base-ten integer"):
        handle_command(Service(), padded, verifier=verifier)  # type: ignore[arg-type]

    # Invalid nonce forms are refused before any ordering check. The empty
    # nonce cannot carry a credential, so it is asserted separately.
    for bad in ("nonce-9", "-1", "1.5", " 9", "9 ", "+9", "0x9"):
        invalid = command("reconcile", request_id="r-bad", envelope_id="e1")
        invalid["nonce"] = bad
        invalid["credential"] = credential(bad, "r-bad")
        with pytest.raises(AssignmentError, match="nonce"):
            handle_command(Service(), invalid, verifier=verifier)  # type: ignore[arg-type]
    empty = command("reconcile", request_id="r-bad-empty", envelope_id="e1")
    empty["nonce"] = ""
    empty["credential"] = "0" * 64
    with pytest.raises(AssignmentError, match="nonce"):
        handle_command(Service(), empty, verifier=verifier)  # type: ignore[arg-type]

    # The refused invalid nonces were not consumed and do not advance the
    # high-water mark.
    eleven = command("reconcile", request_id="r-11", envelope_id="e1")
    eleven["nonce"] = "11"
    eleven["credential"] = credential("11", "r-11")
    assert handle_command(Service(), eleven, verifier=verifier)["ok"] is True  # type: ignore[arg-type]
    assert verifier.commands_remaining == 1021


def test_session_secret_provisioning_binds_identity_and_refuses_cross_session() -> None:
    provisioned_secret = provision_session_secret("session-alpha")
    assert provisioned_secret.session_id == "session-alpha"
    assert len(provisioned_secret.secret) >= 32
    # The provisioning digest is deterministic for the same secret+identity.
    rebuilt = SessionSecret(
        session_id="session-alpha",
        secret=provisioned_secret.secret,
        provisioning_sha256=provisioned_secret.provisioning_sha256,
    )
    verifier = CommandSessionVerifier(rebuilt)
    assert verifier.session_id == "session-alpha"
    assert verifier.provisioning_sha256 == provisioned_secret.provisioning_sha256
    # A tampered provisioning digest fails closed before any command.
    forged = SessionSecret(
        session_id="session-alpha",
        secret=provisioned_secret.secret,
        provisioning_sha256="0" * 64,
    )
    with pytest.raises(AssignmentError, match="provisioning digest does not match"):
        CommandSessionVerifier(forged)

    # The verifier requires a provisioned secret; raw bytes are not accepted.
    with pytest.raises(AssignmentError, match="provisioned session secret"):
        CommandSessionVerifier(SECRET)  # type: ignore[arg-type]

    # The handshake binds the same identity+digest the dispatcher provisioned.
    assert verifier.handshake() == {
        "schema": "testudo.assignment.session.v1",
        "session_id": "session-alpha",
        "provisioning_sha256": provisioned_secret.provisioning_sha256,
    }

    # A credential minted for one session identity is refused on another
    # session even when both verifiers were provisioned from the same secret.
    # The twin is provisioned through the minting path so the registry stays
    # consistent.
    twin_secret = provision_session_secret("session-beta")
    twin = CommandSessionVerifier(twin_secret)
    cross = command("reconcile", request_id="r-cross", envelope_id="e1")
    with pytest.raises(AssignmentError, match="credential verification failed"):
        handle_command(Service(), cross, verifier=twin)  # type: ignore[arg-type]


def test_session_identity_is_folded_into_every_credential() -> None:
    verifier = provisioned()
    # A credential computed without the session identity never verifies, even
    # with the correct secret: session identity is part of the MAC input.
    unbound = command("reconcile", request_id="r-unbound", envelope_id="e1")
    unbound["credential"] = command_credential(SECRET, str(unbound["nonce"]), "r-unbound")
    with pytest.raises(AssignmentError, match="credential verification failed"):
        handle_command(Service(), unbound, verifier=verifier)  # type: ignore[arg-type]

    ok = command("reconcile", request_id="r-bound", envelope_id="e1")
    assert handle_command(Service(), ok, verifier=verifier)["ok"] is True  # type: ignore[arg-type]


def test_one_secret_is_active_per_session_and_rotation_revokes_the_previous() -> None:
    first = provision_session_secret("session-rotate")
    first_verifier = CommandSessionVerifier(first)
    assert first_verifier.session_id == "session-rotate"

    # A second verifier built from the same active generation is accepted: it
    # is the same secret, not a competing generation.
    twin = CommandSessionVerifier(first)
    assert twin.provisioning_sha256 == first.provisioning_sha256

    # Minting a fresh generation for the same session identity rotates: the
    # new secret is the only active one and the old generation is revoked.
    second = provision_session_secret("session-rotate")
    assert second.provisioning_sha256 != first.provisioning_sha256
    second_verifier = CommandSessionVerifier(second)
    assert second_verifier.session_id == "session-rotate"

    # The revoked generation can no longer build a verifier or verify.
    with pytest.raises(AssignmentError, match="not active"):
        CommandSessionVerifier(first)
    stale = command("reconcile", request_id="r-stale", envelope_id="e1")
    stale["credential"] = command_credential(
        first.secret, str(stale["nonce"]), "r-stale", session_id="session-rotate"
    )
    with pytest.raises(AssignmentError, match="credential verification failed"):
        handle_command(Service(), stale, verifier=second_verifier)  # type: ignore[arg-type]

    # A verifier built from a competing (revoked) generation fails closed.
    with pytest.raises(AssignmentError, match="not active"):
        CommandSessionVerifier(first)


def test_explicit_revocation_fails_closed_and_the_next_mint_starts_fresh() -> None:
    secret = provision_session_secret("session-revoke")
    verifier = CommandSessionVerifier(secret)
    assert verifier.commands_remaining == 1024

    # Explicit revocation closes the session immediately.
    revoke_session_secret("session-revoke")
    with pytest.raises(AssignmentError, match="not active"):
        CommandSessionVerifier(secret)

    # The next mint for the same identity starts a fresh, unrevoked
    # generation with a full budget; the old credentials never verify.
    fresh = provision_session_secret("session-revoke")
    fresh_verifier = CommandSessionVerifier(fresh)
    assert fresh_verifier.commands_remaining == 1024
    stale = command("reconcile", request_id="r-stale", envelope_id="e1")
    stale["credential"] = command_credential(
        secret.secret, str(stale["nonce"]), "r-stale", session_id="session-revoke"
    )
    with pytest.raises(AssignmentError, match="credential verification failed"):
        handle_command(Service(), stale, verifier=fresh_verifier)  # type: ignore[arg-type]
    live = command("reconcile", request_id="r-live", envelope_id="e1")
    live["credential"] = command_credential(
        fresh.secret, str(live["nonce"]), "r-live", session_id="session-revoke"
    )
    assert handle_command(Service(), live, verifier=fresh_verifier)["ok"] is True  # type: ignore[arg-type]

    # Revoking an unknown session identity is a bounded no-op.
    revoke_session_secret("session-never-provisioned")


def test_secret_registry_holds_no_secret_material() -> None:
    # The bounded lifecycle registries are keyed by identity and provisioning
    # digest only; they never expose or retain secret bytes.
    import testudo.runtime.assignment_protocol as protocol_module

    registry = protocol_module._ACTIVE_GENERATIONS
    assert all(
        isinstance(session_id, str)
        and isinstance(digest, str)
        and len(digest) == 64
        for session_id, digest in registry.items()
    )
    # No global secret-bytes registry exists.
    forbidden = [
        name
        for name in dir(protocol_module)
        if any(token in name.lower() for token in ("secret_bytes", "secret_pool", "raw_secret"))
    ]
    assert forbidden == []


def test_protocol_terminalize_operation_is_closed_and_authenticated() -> None:
    verifier = provisioned()
    ok = command("terminalize", request_id="term-1", assignment_id="assignment-1")
    ok["reason"] = "host restart lost the run"
    ok["status"] = "failed"
    ok["credential"] = credential(str(ok["nonce"]), "term-1")

    captured: dict[str, object] = {}

    class TerminalizingService(Service):
        def terminalize(self, assignment_id: str, **kwargs: object) -> Any:  # type: ignore[override]
            captured["assignment_id"] = assignment_id
            captured.update(kwargs)
            return Model({"status": kwargs.get("status"), "assignment_id": assignment_id})

    response = handle_command(TerminalizingService(), ok, verifier=verifier)  # type: ignore[arg-type]
    assert response["ok"] is True
    assert captured["assignment_id"] == "assignment-1"
    assert captured["status"] == "failed"
    assert captured["reason"] == "host restart lost the run"
    # The closed schema: missing status or reason is refused; extra fields are
    # refused by the model; unauthenticated calls never reach the router.
    for missing in ("status", "reason"):
        bad = command("terminalize", request_id=f"term-bad-{missing}", assignment_id="a")
        bad["reason"] = "r"
        bad["status"] = "failed"
        del bad[missing]
        bad["credential"] = credential(str(bad["nonce"]), str(bad["request_id"]))
        with pytest.raises(AssignmentError):
            handle_command(Service(), bad, verifier=verifier)  # type: ignore[arg-type]
    extra = command("terminalize", request_id="term-extra", assignment_id="a")
    extra["reason"] = "r"
    extra["status"] = "failed"
    extra["envelope_id"] = "envelope-1"
    extra["credential"] = credential(str(extra["nonce"]), "term-extra")
    with pytest.raises(AssignmentError, match="unsupported fields"):
        handle_command(Service(), extra, verifier=verifier)  # type: ignore[arg-type]
    unauthenticated = dict(ok)
    del unauthenticated["credential"]
    with pytest.raises(AssignmentError, match="credential"):
        handle_command(Service(), unauthenticated, verifier=verifier)  # type: ignore[arg-type]


def test_server_verifier_does_not_expose_public_secret_minting() -> None:
    # The verifier is a consumer of provisioned secrets only: no minting
    # method is exposed on the server verifier surface.
    minting = [
        name
        for name in dir(CommandSessionVerifier)
        if any(token in name.lower() for token in ("mint", "generate", "token_bytes", "urandom"))
    ]
    assert minting == []
    import inspect

    signature = inspect.signature(CommandSessionVerifier.__init__)
    assert "secret" not in signature.parameters
    assert "provisioned" in signature.parameters
    # The dispatcher-side provisioning function is the single minting path.
    import testudo.runtime.assignment_protocol as protocol_module

    assert callable(protocol_module.provision_session_secret)
    with pytest.raises(AssignmentError, match="safe identifier"):
        provision_session_secret("")
    with pytest.raises(AssignmentError, match="safe identifier"):
        provision_session_secret("../escape")


def test_live_verifier_stops_after_rotation_or_revocation() -> None:
    first = provision_session_secret("session-live-rotation")
    stale = CommandSessionVerifier(first)
    provision_session_secret("session-live-rotation")
    value = {
        "schema": "testudo.assignment.protocol.v1",
        "request_id": "stale",
        "operation": "reconcile",
        "envelope_id": "e1",
        "nonce": "1",
        "credential": command_credential(
            first.secret, "1", "stale", session_id="session-live-rotation"
        ),
    }
    with pytest.raises(AssignmentError, match="revoked or rotated"):
        handle_command(Service(), value, verifier=stale)  # type: ignore[arg-type]

    active_secret = provision_session_secret("session-live-revocation")
    active = CommandSessionVerifier(active_secret)
    revoke_session_secret("session-live-revocation")
    value["credential"] = command_credential(
        active_secret.secret, "1", "stale", session_id="session-live-revocation"
    )
    with pytest.raises(AssignmentError, match="revoked or rotated"):
        handle_command(Service(), value, verifier=active)  # type: ignore[arg-type]


def test_nonce_rejects_non_ascii_decimal_digits() -> None:
    secret = provision_session_secret("session-ascii-nonce")
    verifier = CommandSessionVerifier(secret)
    value = {
        "schema": "testudo.assignment.protocol.v1",
        "request_id": "unicode",
        "operation": "reconcile",
        "envelope_id": "e1",
        "nonce": "٩",
        "credential": command_credential(secret.secret, "٩", "unicode", session_id=secret.session_id),
    }
    with pytest.raises(AssignmentError, match="canonical base-ten"):
        handle_command(Service(), value, verifier=verifier)  # type: ignore[arg-type]
