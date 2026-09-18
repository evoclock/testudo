# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Section 6: the closed renderer/bridge capability API.

In-memory service wiring draft/config/ssh/preview/consent/seat endpoints.
The renderer never supplies digests, commands, previews, or consent state;
it may only echo an id, revision, or opaque challenge returned by the bridge
in the exact endpoint field that requires it (R1).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from testudo.seats.config import (
    POLICY_VERSION,
    ConflictError,
    SeatStore,
    StateStore,
    validate_consent,
)
from testudo.seats.consent import consent_digest, consent_text_for
from testudo.seats.controller import SeatContext, SeatError, controller_for, make_executor
from testudo.seats.lifetime import (
    LingerObservation,
    linger_probe_remote_command,
    parse_linger_output,
)
from testudo.seats.ssh import (
    EffectiveSsh,
    HostKeyTrustStore,
    KeyProbeError,
    KeyProbeResult,
    SshDescriptor,
    effective_user,
    exec_remote,
    resolve_effective_ssh,
)
from testudo.seats.transport import EndpointPoller
from testudo.seats.validation import ValidationError, new_uuid4

DRAFT_TTL_SECONDS = 30 * 60
PREVIEW_TTL_SECONDS = 10 * 60
CHALLENGE_TTL_SECONDS = 5 * 60


class ApiError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class Draft:
    draft_id: str
    kind: str  # host | seat
    parent_host_id: str | None
    base_id: str | None
    fields: dict[str, Any]
    revision: int = 1
    expires_at: float = field(default_factory=lambda: time.time() + DRAFT_TTL_SECONDS)


@dataclass
class Preview:
    preview_id: str
    text: str
    digest: str
    effective: EffectiveSsh
    fingerprint: str
    host_lifetime: str
    config_revision: int
    host_id: str
    expires_at: float


@dataclass
class TrustChallenge:
    challenge_id: str
    fingerprint: str
    observed_line: str
    host_id: str
    config_revision: int
    is_replacement: bool
    old_fingerprint: str | None
    expires_at: float


@dataclass
class ForceStopChallenge:
    confirmation_id: str
    seat_id: str
    template: str
    config_revision: int
    consent_digest: str
    expires_at: float


@dataclass
class SeatService:
    """Bridge-owned state for the section 6 endpoints."""

    store: SeatStore
    state_store: StateStore
    trust_store: HostKeyTrustStore
    config_revision: int = 0
    drafts: dict[str, Draft] = field(default_factory=dict)
    previews: dict[str, Preview] = field(default_factory=dict)
    trust_challenges: dict[str, TrustChallenge] = field(default_factory=dict)
    force_stop_challenges: dict[str, ForceStopChallenge] = field(default_factory=dict)

    # --- 1. drafts -----------------------------------------------------------

    def draft_create(
        self,
        kind: str,
        fields: dict[str, Any],
        parent_host_id: str | None = None,
        base_id: str | None = None,
    ) -> dict[str, Any]:
        if kind not in {"host", "seat"}:
            raise ApiError("invalid-kind", "kind must be host or seat")
        if kind == "seat" and parent_host_id is None:
            raise ApiError("missing-parent", "parent_host_id is required for a new seat")
        if "id" in fields or "consent" in fields:
            raise ApiError(
                "generated-field", "id and consent are bridge-generated and cannot be supplied"
            )
        config = self.store.load()
        if base_id is not None:
            fields = self._base_fields(config, kind, base_id, fields)
        else:
            fields = self._validated_new_fields(config, kind, fields, parent_host_id)
        draft_id = new_uuid4()
        self.drafts[draft_id] = Draft(
            draft_id=draft_id,
            kind=kind,
            parent_host_id=parent_host_id,
            base_id=base_id,
            fields=fields,
        )
        return {"draft_id": draft_id, "draft_revision": 1}

    def draft_update(
        self, draft_id: str, draft_revision: int, patch: dict[str, Any]
    ) -> dict[str, Any]:
        draft = self._draft(draft_id, draft_revision)
        if "id" in patch or "consent" in patch:
            raise ApiError(
                "generated-field", "id and consent are bridge-generated and cannot be supplied"
            )
        config = self.store.load()
        merged = {**draft.fields, **patch}
        merged = self._validated_new_fields(config, draft.kind, merged, draft.parent_host_id)
        draft.fields = merged
        draft.revision += 1
        return {"draft_revision": draft.revision}

    def _draft(self, draft_id: str, draft_revision: int) -> Draft:
        draft = self.drafts.get(draft_id)
        if draft is None or draft.expires_at < time.time():
            raise ApiError("unknown-draft", "draft not found or expired")
        if draft.revision != draft_revision:
            raise ApiError("stale-revision", "draft revision mismatch")
        return draft

    def _base_fields(
        self, config: dict[str, Any], kind: str, base_id: str, patch: dict[str, Any]
    ) -> dict[str, Any]:
        if kind == "host":
            for host in config["hosts"]:
                if host["id"] == base_id:
                    fields = {
                        key: value
                        for key, value in host.items()
                        if key not in {"id", "consent", "seats"}
                    }
                    fields.update(patch)
                    return fields
        else:
            for host in config["hosts"]:
                for seat in host["seats"]:
                    if seat["id"] == base_id:
                        fields = {key: value for key, value in seat.items() if key != "id"}
                        fields.update(patch)
                        return fields
        raise ApiError("unknown-id", "base_id not found")

    def _validated_new_fields(
        self,
        config: dict[str, Any],
        kind: str,
        fields: dict[str, Any],
        parent_host_id: str | None,
    ) -> dict[str, Any]:
        """Validate renderer-settable fields by building a candidate object
        and running the full closed-schema validators on it."""
        if kind == "host":
            candidate: dict[str, Any] = {
                "id": new_uuid4(),
                "label": fields.get("label"),
                "ssh": fields.get("ssh"),
                "transport": fields.get("transport"),
                "consent": None,
                "seats": [],
            }
            self._validate_candidate_host(candidate)
            return {
                "label": candidate["label"],
                "ssh": candidate["ssh"],
                "transport": candidate["transport"],
            }
        assert parent_host_id is not None
        self._find_host(config, parent_host_id)  # validates existence
        candidate = {
            "id": new_uuid4(),
            "label": fields.get("label"),
            "template": fields.get("template"),
            "model_id": fields.get("model_id"),
            "port": fields.get("port"),
            "endpoint_host": fields.get("endpoint_host"),
            "ready_timeout": fields.get("ready_timeout"),
        }
        template = fields.get("template")
        if template == "systemd-user":
            candidate["unit"] = fields.get("unit")
        elif template == "control-script":
            candidate["script"] = fields.get("script")
            # subcommands default to start/stop/status (spec 3.4.2)
            candidate["start_subcommand"] = fields.get("start_subcommand", "start")
            candidate["stop_subcommand"] = fields.get("stop_subcommand", "stop")
            candidate["status_subcommand"] = fields.get("status_subcommand", "status")
        elif template == "bare-command":
            candidate["launch_argv"] = fields.get("launch_argv")
            candidate["cwd"] = fields.get("cwd")
        else:
            raise ApiError("invalid-template", "template must be one of the three seat templates")
        from testudo.seats.config import validate_seat

        try:
            validate_seat("seat", candidate)
        except ValidationError as exc:
            raise ApiError("invalid-field", str(exc)) from exc
        self._check_duplicate_endpoint(config, parent_host_id, candidate)
        return {key: value for key, value in candidate.items() if key != "id"}

    def _validate_candidate_host(self, candidate: dict[str, Any]) -> None:
        from testudo.seats.config import validate_host

        try:
            validate_host("host", candidate)
        except ValidationError as exc:
            raise ApiError("invalid-field", str(exc)) from exc

    def _find_host(self, config: dict[str, Any], host_id: str) -> dict[str, Any]:
        for host in config["hosts"]:
            if host["id"] == host_id:
                found: dict[str, Any] = host
                return found
        raise ApiError("unknown-id", f"host not found: {host_id}")

    def _check_duplicate_endpoint(
        self, config: dict[str, Any], host_id: str, seat: dict[str, Any]
    ) -> None:
        key = (seat["endpoint_host"], seat["port"], seat["model_id"])
        for host in config["hosts"]:
            for existing in host["seats"]:
                if (existing["endpoint_host"], existing["port"], existing["model_id"]) == key:
                    raise ApiError(
                        "duplicate-endpoint", "duplicate (endpoint_host, port, model_id)"
                    )

    # --- 2. config -----------------------------------------------------------

    def config_apply(
        self, draft_id: str, draft_revision: int, expected_config_revision: int
    ) -> dict[str, Any]:
        draft = self._draft(draft_id, draft_revision)

        def mutation(config: dict[str, Any]) -> None:
            if draft.kind == "host":
                if draft.base_id is not None:
                    # MED-1: a base_id draft edits the existing host in
                    # place; the id and seats survive, fields are replaced.
                    target = self._find_host_locked(config, draft.base_id)
                    target["label"] = draft.fields["label"]
                    target["ssh"] = draft.fields["ssh"]
                    target["transport"] = draft.fields["transport"]
                else:
                    config["hosts"].append(
                        {
                            "id": new_uuid4(),
                            "label": draft.fields["label"],
                            "ssh": draft.fields["ssh"],
                            "transport": draft.fields["transport"],
                            "consent": None,
                            "seats": [],
                        }
                    )
            else:
                assert draft.parent_host_id is not None
                host = self._find_host_locked(config, draft.parent_host_id)
                if draft.base_id is not None:
                    # MED-1: edit the existing seat in place; the id survives.
                    seat = next((s for s in host["seats"] if s["id"] == draft.base_id), None)
                    if seat is None:
                        raise ApiError("unknown-id", "base_id not found")
                    host["seats"] = [
                        {"id": draft.base_id, **draft.fields} if s["id"] == draft.base_id else s
                        for s in host["seats"]
                    ]
                else:
                    seat = {"id": new_uuid4(), **draft.fields}
                    host["seats"].append(seat)
            # apply-inert: every host's consent is invalidated (S3)
            for host in config["hosts"]:
                host["consent"] = None

        try:
            updated = self.store.mutate(expected_config_revision, mutation)
        except ConflictError as exc:
            raise ApiError("conflict", str(exc)) from exc
        self.config_revision = updated["revision"]
        del self.drafts[draft_id]
        if draft.base_id is not None:
            applied_id = draft.base_id
        elif draft.kind == "host":
            applied_id = updated["hosts"][-1]["id"]
        else:
            host = next(h for h in updated["hosts"] if h["id"] == draft.parent_host_id)
            applied_id = host["seats"][-1]["id"]
        return {"id": applied_id, "config_revision": updated["revision"]}

    def config_delete(
        self, kind: str, object_id: str, expected_config_revision: int
    ) -> dict[str, Any]:
        if kind not in {"host", "seat"}:
            raise ApiError("invalid-kind", "kind must be host or seat")

        def mutation(config: dict[str, Any]) -> None:
            if kind == "host":
                config["hosts"] = [host for host in config["hosts"] if host["id"] != object_id]
            else:
                for host in config["hosts"]:
                    host["seats"] = [seat for seat in host["seats"] if seat["id"] != object_id]
            for host in config["hosts"]:
                host["consent"] = None

        try:
            updated = self.store.mutate(expected_config_revision, mutation)
        except ConflictError as exc:
            raise ApiError("conflict", str(exc)) from exc
        self.config_revision = updated["revision"]
        return {"config_revision": updated["revision"]}

    def config_get(self) -> dict[str, Any]:
        """Omit key material and internal canonical/digest inputs."""
        config: dict[str, Any] = self.store.load()
        redacted: dict[str, Any] = {
            "schema": config["schema"],
            "revision": config["revision"],
            "hosts": [],
        }
        for host in config["hosts"]:
            ssh = dict(host["ssh"])
            ssh.pop("key_path", None)  # key material never returned
            redacted["hosts"].append(
                {
                    "id": host["id"],
                    "label": host["label"],
                    "ssh": ssh,
                    "transport": host["transport"],
                    "consent": (
                        {"accepted_at": host["consent"]["accepted_at"]}
                        if host["consent"] is not None
                        else None
                    ),
                    "seats": host["seats"],
                }
            )
        return redacted

    def _find_host_locked(self, config: dict[str, Any], host_id: str) -> dict[str, Any]:
        for host in config["hosts"]:
            if host["id"] == host_id:
                found: dict[str, Any] = host
                return found
        raise ApiError("unknown-id", f"host not found: {host_id}")

    # --- 3. ssh trust --------------------------------------------------------

    def ssh_probe(self, host_id: str, expected_config_revision: int) -> dict[str, Any]:
        config = self.store.load()
        if config["revision"] != expected_config_revision:
            raise ApiError("conflict", "config revision mismatch")
        host = self._find_host(config, host_id)
        descriptor = SshDescriptor.from_config(host["ssh"], self.trust_store.path)
        try:
            result: KeyProbeResult = self._probe(descriptor)
        except KeyProbeError as exc:
            raise ApiError("probe-failed", str(exc)) from exc
        existing = self.trust_store.known_fingerprint(*self._host_port(host))
        challenge_id = new_uuid4()
        self.trust_challenges[challenge_id] = TrustChallenge(
            challenge_id=challenge_id,
            fingerprint=result.fingerprint,
            observed_line=result.known_hosts_line,
            host_id=host_id,
            config_revision=config["revision"],
            is_replacement=existing is not None and existing != result.fingerprint,
            old_fingerprint=existing,
            expires_at=time.time() + CHALLENGE_TTL_SECONDS,
        )
        return {
            "trust_challenge_id": challenge_id,
            "fingerprint": result.fingerprint,
            "expires_at": self.trust_challenges[challenge_id].expires_at,
        }

    def _probe(self, descriptor: SshDescriptor) -> KeyProbeResult:
        return self._probe_impl(descriptor, Path(self.trust_store.path).parent)

    def _probe_impl(self, descriptor: SshDescriptor, data_dir: Path) -> KeyProbeResult:
        from testudo.seats.ssh import probe_host_key

        return probe_host_key(descriptor, data_dir)

    def ssh_trust(self, trust_challenge_id: str) -> dict[str, Any]:
        challenge = self.trust_challenges.get(trust_challenge_id)
        if challenge is None or challenge.expires_at < time.time():
            raise ApiError("unknown-challenge", "trust challenge not found or expired")
        config = self.store.load()
        if config["revision"] != challenge.config_revision:
            raise ApiError("conflict", "config revision changed since probe")
        host = self._find_host(config, challenge.host_id)
        host_port = self._host_port(host)
        if challenge.is_replacement:
            self.trust_store.replace_for_host(challenge.observed_line, *host_port)
        else:
            self.trust_store.install_initial(challenge.observed_line)
        del self.trust_challenges[trust_challenge_id]

        def mutation(config: dict[str, Any]) -> None:
            target = self._find_host_locked(config, challenge.host_id)
            target["consent"] = None  # trust change invalidates consent (S3)

        try:
            updated = self.store.mutate(config["revision"], mutation)
        except ConflictError as exc:
            # the write failed, but commands still fail closed because S3
            # observes that the trusted fingerprint no longer matches consent
            raise ApiError("conflict", str(exc)) from exc
        self.config_revision = updated["revision"]
        return {"trusted": True, "config_revision": updated["revision"]}

    def _host_port(self, host: dict[str, Any]) -> tuple[str, int | None]:
        ssh = host["ssh"]
        if ssh["kind"] == "explicit":
            return str(ssh["host"]), int(ssh["port"])
        return str(ssh["alias"]), None

    # --- linger probe (U1/BLK-4) ---------------------------------------------

    def probe_linger(self, descriptor: SshDescriptor, effective: EffectiveSsh) -> LingerObservation:
        """The live U1 lifetime probe: the exact rendered remote command
        over one read-only SSH execution, parsed per `parse_linger_output`.
        Resolution or connection failure is ``unknown`` (fail-closed)."""
        user = effective_user(effective)
        if user is None:
            return LingerObservation("unknown")
        result = exec_remote(descriptor, linger_probe_remote_command(user), timeout=15.0)
        return parse_linger_output(result.stdout, result.stderr, result.exit_code)

    # --- 4. preview ----------------------------------------------------------

    def preview_create(self, host_id: str, expected_config_revision: int) -> dict[str, Any]:
        config = self.store.load()
        if config["revision"] != expected_config_revision:
            raise ApiError("conflict", "config revision mismatch")
        host = self._find_host(config, host_id)
        host_port = self._host_port(host)
        trusted = self.trust_store.known_fingerprint(*host_port)
        if trusted is None:
            raise ApiError("untrusted", "host is not trusted; complete ssh.trust first")
        descriptor = SshDescriptor.from_config(host["ssh"], self.trust_store.path)
        try:
            effective = resolve_effective_ssh(descriptor)
        except Exception as exc:
            raise ApiError("resolve-failed", str(exc)) from exc
        # BLK-4: the live linger observation binds the digest input
        linger = self.probe_linger(descriptor, effective)
        digest = consent_digest(
            host_config_excluding_consent=self._host_excluding_consent(host),
            ssh_effective=effective,
            trusted_host_key_fingerprint=trusted,
            host_lifetime=linger.value,
            transport=host["transport"],
            ordered_seats=host["seats"],
        )
        preview_id = new_uuid4()
        text = self._preview_text(host, effective, trusted, linger)
        self.previews[preview_id] = Preview(
            preview_id=preview_id,
            text=text,
            digest=digest,
            effective=effective,
            fingerprint=trusted,
            host_lifetime=linger.value,
            config_revision=config["revision"],
            host_id=host_id,
            expires_at=time.time() + PREVIEW_TTL_SECONDS,
        )
        return {
            "preview_id": preview_id,
            "expires_at": self.previews[preview_id].expires_at,
            "text": text,
        }

    def _host_excluding_consent(self, host: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": host["id"],
            "label": host["label"],
            "ssh": host["ssh"],
            "transport": host["transport"],
            "seats": host["seats"],
        }

    def _preview_text(
        self,
        host: dict[str, Any],
        effective: EffectiveSsh,
        trusted: str,
        linger: LingerObservation,
    ) -> str:
        lines = [
            f"host: {host['label']}",
            f"transport: {host['transport']['kind']}",
            f"trusted key: {trusted}",
            f"linger: {linger.value}",
            "effective ssh configuration (ordered):",
        ]
        for key, value in effective.ordered_pairs:
            lines.append(f"  {key} {value}")
        lines.append(f"ssh binary: {effective.binary_path} ({effective.binary_version})")
        lines.append(f"ssh binary sha256: {effective.binary_sha256}")
        for seat in host["seats"]:
            controller = controller_for(
                _preview_context(host, seat, self.trust_store.path, self.state_store)
            )
            # MED-2: every template's exact start/stop argv is previewed
            lines.append(f"seat {seat['label']} ({seat['template']}):")
            lines.append(f"start: {controller._operation_argv('_start_locked')}")
            try:
                lines.append(f"stop: {controller._operation_argv('_stop_locked')}")
            except SeatError:
                # Template C stop needs a persisted PID record; before the
                # first start the preview shows the identity-checked shape.
                lines.append(
                    "stop: identity-checked C_PID_V1 stop (requires a persisted PID record)"
                )
        lines.append(consent_text_for(str(host["label"])))
        return "\n".join(lines)

    # --- 5. consent ----------------------------------------------------------

    def consent_confirm(self, preview_id: str) -> dict[str, Any]:
        preview = self.previews.get(preview_id)
        if preview is None or preview.expires_at < time.time():
            raise ApiError("unknown-preview", "preview not found or expired")
        config = self.store.load()
        if config["revision"] != preview.config_revision:
            raise ApiError("stale-preview", "config changed since preview; request a new preview")
        host = self._find_host(config, preview.host_id)
        host_port = self._host_port(host)
        trusted = self.trust_store.known_fingerprint(*host_port)
        if trusted is None or trusted != self._challenge_fingerprint(preview):
            raise ApiError("stale-preview", "trust changed since preview; request a new preview")
        descriptor = SshDescriptor.from_config(host["ssh"], self.trust_store.path)
        try:
            rerun = resolve_effective_ssh(descriptor)
        except Exception as exc:
            raise ApiError("resolve-failed", str(exc)) from exc
        if rerun.canonical_json() != preview.effective.canonical_json():
            raise ApiError("stale-preview", "effective SSH changed; request a new preview")
        # BLK-4: the digest binds the immediately refreshed lifetime value
        linger = self.probe_linger(descriptor, rerun)
        digest = consent_digest(
            host_config_excluding_consent=self._host_excluding_consent(host),
            ssh_effective=rerun,
            trusted_host_key_fingerprint=trusted,
            host_lifetime=linger.value,
            transport=host["transport"],
            ordered_seats=host["seats"],
        )
        if digest != preview.digest:
            raise ApiError("stale-preview", "digest mismatch; request a new preview")
        consent = {
            "digest": digest,
            "accepted_at": _utcnow(),
            "policy_version": POLICY_VERSION,
            "ssh_effective_sha256": rerun.sha256(),
            "host_key_fingerprint": trusted,
        }
        validate_consent("consent", consent)

        def mutation(config: dict[str, Any]) -> None:
            target = self._find_host_locked(config, preview.host_id)
            target["consent"] = consent

        try:
            updated = self.store.mutate(config["revision"], mutation)
        except ConflictError as exc:
            raise ApiError("conflict", str(exc)) from exc
        del self.previews[preview_id]
        self.config_revision = updated["revision"]
        return {"consented": True, "config_revision": updated["revision"]}

    def _challenge_fingerprint(self, preview: Preview) -> str:
        """MED-3: the trusted fingerprint bound at preview time."""
        return preview.fingerprint

    # --- 6. seat operations --------------------------------------------------

    def seat_force_stop_challenge(self, seat_id: str) -> dict[str, Any]:
        config = self.store.load()
        host, seat = self._find_seat(config, seat_id)
        if seat["template"] == "control-script":
            raise ApiError("unsupported", "unsupported: host-side intervention required")
        consent = host["consent"]
        if consent is None:
            raise ApiError("no-consent", "re-confirmation required")
        # HIGH-2: the challenge binds the current consent digest
        confirmation_id = new_uuid4()
        self.force_stop_challenges[confirmation_id] = ForceStopChallenge(
            confirmation_id=confirmation_id,
            seat_id=seat_id,
            template=seat["template"],
            config_revision=config["revision"],
            consent_digest=consent["digest"],
            expires_at=time.time() + CHALLENGE_TTL_SECONDS,
        )
        return {
            "confirmation_id": confirmation_id,
            "expires_at": self.force_stop_challenges[confirmation_id].expires_at,
        }

    def seat_operate(
        self, seat_id: str, operation: str, confirmation_id: str | None = None
    ) -> dict[str, Any]:
        if operation not in {"start", "stop", "force-stop"}:
            raise ApiError("invalid-operation", "operation must be start, stop, or force-stop")
        config = self.store.load()
        host, seat = self._find_seat(config, seat_id)
        # R1: operation resolves its seat entirely from the current
        # server-side config, requires current trust and consent.
        host_port = self._host_port(host)
        trusted = self.trust_store.known_fingerprint(*host_port)
        if trusted is None:
            raise ApiError("untrusted", "host is not trusted")
        consent = host["consent"]
        if consent is None:
            raise ApiError("no-consent", "re-confirmation required")
        if seat["template"] == "control-script" and operation == "force-stop":
            raise ApiError("unsupported", "unsupported: host-side intervention required")
        # BLK-3: command-time S1 re-resolution and consent-drift comparison.
        # The operation resolves its seat entirely from the current
        # server-side config, requires current trust and consent, and
        # repeats S1 before SSH (R1).
        descriptor = SshDescriptor.from_config(host["ssh"], self.trust_store.path)
        try:
            effective = resolve_effective_ssh(descriptor)
        except Exception as exc:
            raise ApiError("re-confirmation required", f"ssh -G failed: {exc}") from exc
        if effective.sha256() != consent["ssh_effective_sha256"]:
            raise ApiError("re-confirmation required", "effective SSH drifted since consent")
        if trusted != consent["host_key_fingerprint"]:
            raise ApiError("re-confirmation required", "trusted host key drifted since consent")
        linger = self.probe_linger(descriptor, effective)
        digest = consent_digest(
            host_config_excluding_consent=self._host_excluding_consent(host),
            ssh_effective=effective,
            trusted_host_key_fingerprint=trusted,
            host_lifetime=linger.value,
            transport=host["transport"],
            ordered_seats=host["seats"],
        )
        if digest != consent["digest"]:
            raise ApiError("re-confirmation required", "consent digest drifted")
        if operation == "force-stop":
            challenge = self.force_stop_challenges.get(confirmation_id or "")
            if (
                challenge is None
                or challenge.expires_at < time.time()
                or challenge.seat_id != seat_id
                or challenge.template != seat["template"]
                or challenge.config_revision != config["revision"]
                or challenge.consent_digest != consent["digest"]  # HIGH-2
            ):
                raise ApiError("challenge-required", "a valid force-stop challenge is required")
            del self.force_stop_challenges[confirmation_id or ""]  # single-use
        context = self._seat_context(
            config, host, seat, trusted, effective=effective, linger=linger
        )
        controller = controller_for(context)
        if operation == "start":
            outcome = controller.start()
        elif operation == "stop":
            outcome = controller.stop()
        else:
            outcome = controller.force_stop()
        return {
            "state": outcome.state,
            "error": outcome.error,
            "detail": outcome.detail,
            "occupant_models": list(outcome.occupant_models),
        }

    def seat_inspect(self, seat_id: str) -> dict[str, Any]:
        config = self.store.load()
        host, seat = self._find_seat(config, seat_id)
        host_port = self._host_port(host)
        trusted = self.trust_store.known_fingerprint(*host_port)
        if trusted is None:
            raise ApiError("untrusted", "host is not trusted")
        descriptor = SshDescriptor.from_config(host["ssh"], self.trust_store.path)
        try:
            effective = resolve_effective_ssh(descriptor)
        except Exception as exc:
            raise ApiError("resolve-failed", str(exc)) from exc
        linger = self.probe_linger(descriptor, effective)
        context = self._seat_context(
            config, host, seat, trusted, effective=effective, linger=linger
        )
        controller = controller_for(context)
        result = controller.inspect()
        result["linger"] = linger.value
        return result

    def _find_seat(
        self, config: dict[str, Any], seat_id: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        for host in config["hosts"]:
            for seat in host["seats"]:
                if seat["id"] == seat_id:
                    return host, seat
        raise ApiError("unknown-id", f"seat not found: {seat_id}")

    def _seat_context(
        self,
        config: dict[str, Any],
        host: dict[str, Any],
        seat: dict[str, Any],
        trusted: str | None,
        *,
        effective: EffectiveSsh | None = None,
        linger: LingerObservation | None = None,
    ) -> SeatContext:
        """BLK-2: a real context — live poller, the bridge state store,
        a live U1 linger observation, and a read-only executor."""
        descriptor = SshDescriptor.from_config(host["ssh"], self.trust_store.path)
        ssh_host, ssh_port = self._host_port(host)
        if linger is None:
            resolved = effective if effective is not None else self._resolve(descriptor)
            linger = self.probe_linger(descriptor, resolved)
        return SeatContext(
            host_id=host["id"],
            seat_id=seat["id"],
            seat=seat,
            descriptor=descriptor,
            endpoint_host=seat["endpoint_host"],
            endpoint_port=seat["port"],
            ssh_hostname=ssh_host,
            ssh_port=ssh_port or 22,
            config_revision=config["revision"],
            poller=EndpointPoller(),
            linger=linger,
            stores=self.store,
            state_store=self.state_store,
            transport=host["transport"],
            executor=make_executor(descriptor),
        )

    def _resolve(self, descriptor: SshDescriptor) -> EffectiveSsh:
        try:
            return resolve_effective_ssh(descriptor)
        except Exception:
            return EffectiveSsh((), "", "", "")

    # --- 7. hosted keys ------------------------------------------------------

    def provider_key_write(self, provider_id: str, key: str) -> dict[str, Any]:
        from testudo.seats.credentials import CredentialStoreError, set_provider_key

        try:
            set_provider_key(provider_id, key)
        except CredentialStoreError as exc:
            raise ApiError("credential-store", str(exc)) from exc
        return {"provider_id": provider_id, "state": "set"}

    def provider_key_state(self, provider_id: str) -> dict[str, Any]:
        from testudo.seats.credentials import key_state

        state = key_state(provider_id)
        return {"provider_id": state.provider_id, "state": state.state}


def _preview_context(
    host: dict[str, Any],
    seat: dict[str, Any],
    known_hosts: Any,
    state_store: StateStore | None = None,
) -> SeatContext:
    from pathlib import Path

    from testudo.seats.ssh import SshDescriptor

    return SeatContext(
        host_id=host["id"],
        seat_id=seat["id"],
        seat=seat,
        descriptor=SshDescriptor.from_config(host["ssh"], Path(known_hosts)),
        endpoint_host=seat["endpoint_host"],
        endpoint_port=seat["port"],
        ssh_hostname="",
        ssh_port=22,
        config_revision=0,
        poller=EndpointPoller(),
        linger=LingerObservation("unknown"),
        state_store=state_store,
        transport=host["transport"],
    )


def _utcnow() -> str:
    import datetime

    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
