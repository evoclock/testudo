# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""D2 probe contract: direct connection with proxy/environment lookup
disabled, only ``GET /v1/models``, no redirects, 2-second connect and read
deadlines, 1 MiB abort, and strict response validation."""

from __future__ import annotations

import http.client
import json
import socket
from dataclasses import dataclass

from testudo.seats.validation import ValidationError, validate_model_id

CONNECT_TIMEOUT_SECONDS = 2.0
READ_TIMEOUT_SECONDS = 2.0
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_MODELS = 1000
LOCAL_PORTS = (8000, 8080, 8893, 30000, 1234, 11434)


@dataclass(frozen=True)
class ProbeResult:
    ok: bool
    models: tuple[str, ...] = ()
    reason: str = ""


class _NoProxySocket(socket.socket):
    """Plain socket; the probe contract disables proxy/environment lookup by
    never consulting them (http.client does not by default; this documents
    and pins the direct-connection behavior)."""


def _connect(host: str, port: int, ip: str) -> socket.socket:
    """Connect directly to ``ip`` (never resolving again, D3): the caller
    passes the one eligible address it selected."""
    sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT_SECONDS)
    try:
        sock.connect((ip, port))
        sock.settimeout(READ_TIMEOUT_SECONDS)
        return sock
    except OSError:
        sock.close()
        raise


def probe_models(host: str, port: int, ip: str) -> ProbeResult:
    """One D2 HTTP request: GET /v1/models, direct connection, bounded."""
    sock = None
    try:
        sock = _connect(host, port, ip)
        connection = http.client.HTTPConnection(host, port, timeout=READ_TIMEOUT_SECONDS)
        connection.sock = sock  # inject the pre-connected direct socket
        connection.request("GET", "/v1/models", headers={"Accept": "application/json"})
        response = connection.getresponse()
        content_type = response.getheader("Content-Type", "")
        if not content_type.lower().startswith("application/json"):
            return ProbeResult(False, reason="wrong-content-type")
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            return ProbeResult(False, reason="too-large")
        try:
            document = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return ProbeResult(False, reason="malformed-json")
        if not isinstance(document, dict) or "data" not in document:
            # one top-level object whose data member is an array; anything
            # else invalidates the complete response
            return ProbeResult(False, reason="not-an-object")
        data = document.get("data")
        if not isinstance(data, list) or len(data) > MAX_MODELS:
            return ProbeResult(False, reason="bad-data-array")
        models: list[str] = []
        for entry in data:
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                return ProbeResult(False, reason="bad-model-entry")
            try:
                validate_model_id("model-id", entry["id"])
            except ValidationError:
                return ProbeResult(False, reason="invalid-model-id")
            models.append(entry["id"])
        return ProbeResult(True, tuple(models))
    except (OSError, http.client.HTTPException, TimeoutError):
        return ProbeResult(False, reason="connection-failed")
    finally:
        if sock is not None:
            sock.close()
