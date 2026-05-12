"""
Module: testudo.mcp_servers.base

Purpose: minimal in-house JSON-RPC 2.0 MCP server scaffold. STDIO transport
only. Implements the handshake, ``tools/list``, and ``tools/call`` methods
defined by the Model Context Protocol. No external dependencies; runs as a
local subprocess.

Inputs: JSON-RPC 2.0 messages on stdin.

Outputs: JSON-RPC 2.0 responses on stdout. Log records on stderr.

Assumptions: STDIO is line-delimited (one JSON object per line). The host
launches one server per process; process boundary is the isolation unit
per slide 12 of the MCP presentation. No HTTP/SSE transport is exposed.

Failure modes: malformed JSON yields a -32700 Parse error response;
unknown method yields a -32601 Method-not-found; tool-handler exceptions
are wrapped as ``isError: true`` results so the host can decide whether
to retry or surface the error to the model.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

JSONDict = dict[str, Any]
ToolHandler = Callable[[JSONDict], JSONDict]


@dataclass(slots=True)
class ToolSpec:
    """One tool exposed by an MCP server."""

    name: str
    description: str
    input_schema: JSONDict
    handler: ToolHandler


@dataclass(slots=True)
class BaseMCPServer:
    """Minimal STDIO-transport MCP server."""

    name: str
    tools: dict[str, ToolSpec] = field(default_factory=dict)
    protocol_version: str = "2025-06-18"

    def register(self, spec: ToolSpec) -> None:
        """Register one tool with this server. Re-registration is rejected."""
        if spec.name in self.tools:
            raise ValueError(f"Tool already registered: {spec.name}")
        self.tools[spec.name] = spec

    def handle(self, request: JSONDict) -> JSONDict | None:
        """Dispatch a single JSON-RPC request and return the response.

        Returns ``None`` for notifications (requests without an ``id``).
        """
        method = request.get("method", "")
        req_id = request.get("id")

        if method == "initialize":
            result = {
                "protocolVersion": self.protocol_version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": self.name, "version": "0.1.5"},
            }
            return self._envelope(req_id, result=result)

        if method == "tools/list":
            tools = [
                {
                    "name": spec.name,
                    "description": spec.description,
                    "inputSchema": spec.input_schema,
                }
                for spec in self.tools.values()
            ]
            return self._envelope(req_id, result={"tools": tools})

        if method == "tools/call":
            params = request.get("params") or {}
            tool_name = params.get("name")
            arguments = params.get("arguments") or {}

            if not isinstance(tool_name, str) or tool_name not in self.tools:
                return self._envelope(
                    req_id,
                    error={"code": -32601, "message": f"Unknown tool: {tool_name!r}"},
                )

            try:
                result = self.tools[tool_name].handler(arguments)
            except Exception as exc:
                result = {
                    "isError": True,
                    "content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}],
                }
            return self._envelope(req_id, result=result)

        if req_id is None:
            return None
        return self._envelope(
            req_id,
            error={"code": -32601, "message": f"Method not found: {method}"},
        )

    def run(self, stdin: Any = None, stdout: Any = None) -> None:
        """Read one JSON-RPC request per line from stdin and write the response."""
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout

        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except json.JSONDecodeError as exc:
                response = self._envelope(None, error={"code": -32700, "message": str(exc)})
            else:
                response = self.handle(request)
            if response is not None:
                stdout.write(json.dumps(response) + "\n")
                stdout.flush()

    @staticmethod
    def _envelope(
        req_id: Any,
        *,
        result: JSONDict | None = None,
        error: JSONDict | None = None,
    ) -> JSONDict:
        envelope: JSONDict = {"jsonrpc": "2.0", "id": req_id}
        if error is not None:
            envelope["error"] = error
        else:
            envelope["result"] = result or {}
        return envelope
