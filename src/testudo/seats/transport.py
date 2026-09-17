# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""T1/T2 endpoint transports and polling.

Transport is exactly one of trusted-lan (HTTP only to a fresh connected peer
in RFC1918 or 100.64.0.0/10 after per-host explicit trust), https (verified
TLS, no opt-out), or ssh-tunnel (Testudo-managed ``ssh -W`` standard-I/O
forwarding so no listening socket is created).
"""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

from testudo.seats.probe import MAX_RESPONSE_BYTES, READ_TIMEOUT_SECONDS
from testudo.seats.render import MAX_OUTPUT_BYTES
from testudo.seats.ssh import SshDescriptor

ENDPOINT_STATES = (
    "closed",
    "invalid",
    "occupied-known",
    "occupied-unknown",
    "unauthorized",
    "tls-error",
    "indeterminate",
)


@dataclass
class Observation:
    """One endpoint observation with monotonic sequence and timestamp (T1)."""

    sequence: int
    timestamp: float
    host_state: str  # reachable | unreachable
    endpoint_state: str
    models: tuple[str, ...] = ()
    detail: str = ""


@dataclass
class EndpointPoller:
    """Polls one endpoint per its transport; model ids are occupancy
    evidence, not authentication."""

    sequence_counter: int = 0
    observations: list[Observation] = field(default_factory=list)

    def poll(
        self,
        transport: dict[str, Any],
        endpoint_host: str,
        endpoint_port: int,
        seat_model_id: str,
        descriptor: SshDescriptor | None = None,
        connected_peer: str | None = None,
    ) -> Observation:
        self.sequence_counter += 1
        sequence = self.sequence_counter
        if transport.get("kind") == "https":
            observation = self._poll_https(endpoint_host, endpoint_port)
        elif transport.get("kind") == "ssh-tunnel":
            assert descriptor is not None, "ssh-tunnel requires a descriptor"
            observation = self._poll_tunnel(descriptor, endpoint_host, endpoint_port)
        else:
            assert connected_peer is not None, "trusted-lan requires a connected peer"
            observation = self._poll_trusted_lan(endpoint_host, endpoint_port, connected_peer)
        # classify occupancy against the exact seat model id (T2)
        if observation.endpoint_state == "closed" and observation.models:
            if tuple(observation.models) == (seat_model_id,):
                observation.endpoint_state = "occupied-known"
            else:
                observation.endpoint_state = "occupied-unknown"
        observation.sequence = sequence
        observation.timestamp = time.time()
        self.observations.append(observation)
        return observation

    def latest(self) -> Observation | None:
        return self.observations[-1] if self.observations else None

    def _poll_https(self, host: str, port: int) -> Observation:
        context = ssl.create_default_context()  # verified TLS, no opt-out
        try:
            connection = http.client.HTTPSConnection(
                host, port, timeout=READ_TIMEOUT_SECONDS, context=context
            )
            connection.request("GET", "/v1/models")
            response = connection.getresponse()
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                return Observation(0, 0.0, "reachable", "indeterminate", detail="overflow")
            if response.status in (401, 403):
                return Observation(0, 0.0, "reachable", "unauthorized")
            if response.status != 200:
                return Observation(
                    0, 0.0, "reachable", "invalid", detail=f"status {response.status}"
                )
            if not _json_content_type(response.getheader("Content-Type", "")):
                return Observation(0, 0.0, "reachable", "invalid", detail="wrong-content-type")
            models = _parse_models(body)
            if models is None:
                return Observation(0, 0.0, "reachable", "invalid", detail="malformed")
            return Observation(0, 0.0, "reachable", "closed", models=tuple(models))
        except ssl.SSLError as exc:
            return Observation(0, 0.0, "reachable", "tls-error", detail=str(exc))
        except (OSError, http.client.HTTPException):
            return Observation(0, 0.0, "unreachable", "closed", detail="connect-failed")

    def _poll_trusted_lan(self, host: str, port: int, connected_peer: str) -> Observation:
        from testudo.seats.address_classes import is_discovery_eligible

        # D3/T1: revalidate the connected peer before sending any HTTP byte.
        if not is_discovery_eligible(connected_peer):
            return Observation(0, 0.0, "unreachable", "indeterminate", detail="ineligible-peer")
        try:
            sock = socket.socket(socket.AF_INET6 if ":" in connected_peer else socket.AF_INET)
            sock.settimeout(READ_TIMEOUT_SECONDS)
            sock.connect((connected_peer, port))
            peer = sock.getpeername()[0]
            if not is_discovery_eligible(peer):
                sock.close()
                return Observation(
                    0, 0.0, "unreachable", "indeterminate", detail="peer-substituted"
                )
            connection = http.client.HTTPConnection(host, port, timeout=READ_TIMEOUT_SECONDS)
            connection.sock = sock
            connection.request("GET", "/v1/models")
            response = connection.getresponse()
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                return Observation(0, 0.0, "reachable", "indeterminate", detail="overflow")
            if response.status in (401, 403):
                return Observation(0, 0.0, "reachable", "unauthorized")
            if response.status != 200:
                return Observation(
                    0, 0.0, "reachable", "invalid", detail=f"status {response.status}"
                )
            if not _json_content_type(response.getheader("Content-Type", "")):
                return Observation(0, 0.0, "reachable", "invalid", detail="wrong-content-type")
            models = _parse_models(body)
            if models is None:
                return Observation(0, 0.0, "reachable", "invalid", detail="malformed")
            return Observation(0, 0.0, "reachable", "closed", models=tuple(models))
        except (OSError, http.client.HTTPException):
            return Observation(0, 0.0, "unreachable", "closed", detail="connect-failed")

    def _poll_tunnel(self, descriptor: SshDescriptor, host: str, port: int) -> Observation:
        """One D2 HTTP request written to SSH stdin; the bounded response is
        parsed from stdout; SSH closes when the request ends."""
        argv = _tunnel_argv(descriptor, host, port)
        request = b"GET /v1/models HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n"
        try:
            proc = subprocess.run(
                argv,
                input=request,
                capture_output=True,
                shell=False,
                timeout=READ_TIMEOUT_SECONDS + 5,
                check=False,
            )
        except subprocess.TimeoutExpired:
            # the tunnel was established (ConnectTimeout bounds the SSH
            # connect below); the endpoint exceeded the D2 read deadline
            return Observation(0, 0.0, "reachable", "indeterminate", detail="timeout")
        except OSError:
            return Observation(0, 0.0, "unreachable", "indeterminate", detail="ssh-failed")
        if len(proc.stdout) > MAX_OUTPUT_BYTES:
            return Observation(0, 0.0, "reachable", "indeterminate", detail="overflow")
        status = _http_status_line(proc.stdout)
        if status is None:
            return _classify_tunnel_failure(proc.stderr)
        if status in (401, 403):
            return Observation(0, 0.0, "reachable", "unauthorized")
        if status != 200:
            return Observation(0, 0.0, "reachable", "invalid", detail=f"status {status}")
        if not _json_content_type(_http_header(proc.stdout, b"content-type")):
            return Observation(0, 0.0, "reachable", "invalid", detail="wrong-content-type")
        body = _extract_http_body(proc.stdout)
        if body is None:
            return Observation(0, 0.0, "unreachable", "indeterminate", detail="no-response")
        if len(body) > MAX_RESPONSE_BYTES:
            return Observation(0, 0.0, "reachable", "indeterminate", detail="overflow")
        models = _parse_models(body)
        if models is None:
            return Observation(0, 0.0, "reachable", "invalid", detail="malformed")
        return Observation(0, 0.0, "reachable", "closed", models=tuple(models))


def _classify_tunnel_failure(stderr: bytes) -> Observation:
    """T1: with ``ExitOnForwardFailure=yes`` a forwarded connection that
    the *remote* side refuses proves the SSH host is reachable and nothing
    listens on the endpoint (closed); every other failure (connect, auth,
    host key, protocol) leaves the host unreachable/indeterminate."""
    text = stderr.decode("utf-8", errors="replace")
    if "open failed: connect failed" in text:
        # the channel reached the remote side; the endpoint port refused
        return Observation(0, 0.0, "reachable", "closed", detail="endpoint-refused")
    return Observation(0, 0.0, "unreachable", "indeterminate", detail="ssh-failed")


def _tunnel_argv(descriptor: SshDescriptor, host: str, port: int) -> list[str]:
    """``-T -o ExitOnForwardFailure=yes -W <host>:<port>`` before the
    destination; ClearAllForwardings=yes from the descriptor; shell:false;
    no remote-command element."""
    from testudo.seats.ssh import mandatory_ssh_options

    argv = ["ssh", *mandatory_ssh_options(descriptor.known_hosts_path)]
    # user-derived options (port/key) then the tunnel arguments
    destination_args = descriptor.destination_args()
    destination = destination_args[-1]
    argv.extend(destination_args[:-1])
    argv.extend(
        [
            "-T",
            "-o",
            "ExitOnForwardFailure=yes",
            "-W",
            f"{host}:{port}",
        ]
    )
    argv.append(destination)
    return argv


def _json_content_type(value: str) -> bool:
    """D2: the response Content-Type must be application/json (parameters
    such as charset are permitted)."""
    return value.strip().lower().startswith("application/json")


def _http_status_line(raw: bytes) -> int | None:
    """The numeric status of the first HTTP response line."""
    first = raw.split(b"\r\n", 1)[0]
    parts = first.split(b" ", 2)
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def _http_header(raw: bytes, name: bytes) -> str:
    """The first header value for ``name`` from the raw response, if any."""
    head = raw.split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n"):
        if line.lower().startswith(name + b":"):
            return line.split(b":", 1)[1].strip().decode("latin-1", errors="replace")
    return ""


def _parse_models(body: bytes) -> list[str] | None:
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(document, dict) or "data" not in document:
        return None
    data = document["data"]
    if not isinstance(data, list) or len(data) > 1000:
        return None
    models: list[str] = []
    for entry in data:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            return None
        models.append(entry["id"])
    return models


def _extract_http_body(raw: bytes) -> bytes | None:
    """Split an HTTP/1.0 response into its body."""
    separator = raw.find(b"\r\n\r\n")
    if separator == -1:
        return None
    return raw[separator + 4 :]
