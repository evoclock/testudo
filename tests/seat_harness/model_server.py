"""Fixture model servers: OpenAI-compatible /v1/models endpoints.

SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later

Spec section 8 requires trivial HTTP servers answering GET /v1/models with a
configurable model id, controllable latency, failure modes (connection
refused, timeout, malformed JSON, oversized responses), and start/stop
control. These run inside the Linux fixture container (for G1's post-session
poll) and on the host loopback (for G6/G7 endpoint polling), using only the
standard library so the harness stays dependency-free offline.
"""

from __future__ import annotations

import json
import socket
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler


class ModelServerControl:
    """Handle-level shared state, mutated live by the test."""

    def __init__(self, model_id: str) -> None:
        self.model_id = model_id
        self.serving = True
        self.latency_seconds = 0.0
        self.mode = "ok"  # ok | malformed | oversized | wrong_content_type | hang
        self.request_count = 0


class _Handler(BaseHTTPRequestHandler):
    control: ModelServerControl  # class attribute set per-server

    def do_GET(self) -> None:
        control = self.control
        control.request_count += 1
        if control.latency_seconds:
            time.sleep(control.latency_seconds)
        if not control.serving:
            # Close the connection without a response: "connection refused /
            # closed" failure mode from the poller's perspective.
            self.close_connection = True
            return
        if control.mode == "hang":
            time.sleep(30)  # exceeds any D2 read deadline; test kills the server
            return
        body: bytes
        if control.mode == "malformed":
            body = b"{not json at all"
        elif control.mode == "oversized":
            # 1,001 model objects, each > 1 KiB: well past the 1 MiB cap.
            model = {"id": "m" + "x" * 1200}
            body = json.dumps({"data": [model] * 1001}).encode()
        elif control.mode == "wrong_content_type":
            body = json.dumps({"data": [{"id": control.model_id}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        else:
            body = json.dumps({"data": [{"id": control.model_id}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass  # silent; harness asserts on state, not logs


class FixtureModelServer:
    """A loopback HTTP server emulating an OpenAI-compatible model endpoint."""

    def __init__(self, model_id: str, port: int | None = None) -> None:
        self.control = ModelServerControl(model_id)
        self._port = port
        self._bound_port: int | None = None  # actual port once started
        self._server: socketserver.TCPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        assert self._server is not None
        return int(self._server.server_address[1])

    def start(self) -> None:
        control = self.control

        class _Bound(_Handler):
            pass

        _Bound.control = control

        class _Srv(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self._server = _Srv(("127.0.0.1", self._port or 0), _Bound)
        self._bound_port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop serving immediately (open connections are cut)."""
        self.control.serving = False
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def hard_kill(self) -> None:
        """Simulate connection-refused by closing the listening socket now."""
        self.stop()

    def poll_models(self, timeout: float = 2.0) -> list[str] | None:
        """A D2-shaped poll from the harness side (direct, no proxy env).

        Works even after ``stop()``/``hard_kill()`` (connection refused ->
        None), which is exactly the post-session teardown case G7 exercises.
        """
        port = self._bound_port
        if port is None:
            return None
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(b"GET /v1/models HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > 1024 * 1024:
                        return None  # 1 MiB cap exceeded
                raw = b"".join(chunks)
            head, _, body = raw.partition(b"\r\n\r\n")
            if b"200" not in head.split(b"\r\n")[0]:
                return None
            if b"application/json" not in head.lower():
                return None
            data = json.loads(body)
            models = data.get("data")
            if not isinstance(models, list):
                return None
            return [m["id"] for m in models if isinstance(m, dict) and isinstance(m.get("id"), str)]
        except (OSError, ValueError, KeyError):
            return None
