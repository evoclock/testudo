#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fixture model server that IGNORES SIGTERM — forces C_PID_V1's TERM-then-
KILL escalation (G2). Exits only on SIGKILL."""

import json
import signal
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = json.dumps({"data": [{"id": "fixture-model"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        pass


signal.signal(signal.SIGTERM, signal.SIG_IGN)  # stubborn: TERM is ignored
HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
