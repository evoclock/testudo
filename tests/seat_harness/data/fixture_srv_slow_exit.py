#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fixture model server that exits slowly on SIGTERM (1 s) — used to keep
the C_PID_V1 TERM/wait/KILL window observable and to distinguish the
fast-exit race from genuine escalation."""

import json
import signal
import sys
import time
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


server = HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler)


def _bye(signum: int, frame: object) -> None:
    time.sleep(1.0)
    sys.exit(0)


signal.signal(signal.SIGTERM, _bye)
server.serve_forever()
