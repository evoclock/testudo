"""
Module: testudo.mcp_servers.file_extractor

Purpose: read-only document extraction MCP server. Parses attachments
(PDF, DOCX, PPTX, HTML, JSON, plain text) and returns cleaned text with
metadata, comments, hidden-unicode, and external-link payloads stripped.
This is the extraction half of the extraction-vs-action separation
mandated by MCP presentation v4 slide 25.

Inputs: ``extract_text`` tool calls with a ``path`` field.

Outputs: a structured result with the cleaned text, the format used, byte /
char counts, and a list of stripped hidden-unicode findings.

Assumptions: the server has NO write capability. Extraction primitives
live in :mod:`testudo.connectors.extract` so the orchestrator's
``connectors.extract_document`` tool and this MCP server share one
implementation.

References:

- MCP presentation v4 slide 25: "One agent parses the document in a
  restricted environment. A second agent, with stronger approvals, acts
  only on the cleaned summary."
- Snyk ToxicSkills (slide 19): attachments and linked content are a
  supply-chain attack surface.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from testudo.connectors.extract import EXTRACTORS, extract_document
from testudo.mcp_servers.base import BaseMCPServer, ToolSpec
from testudo.sanitisers.unicode_payload import strip_hidden


def _extract_text(arguments: dict[str, Any]) -> dict[str, Any]:
    """``extract_text`` handler: dispatch on suffix, then strip hidden payloads."""
    raw_path = arguments.get("path")
    if not isinstance(raw_path, str):
        return _err("path is required")

    path = Path(raw_path)
    if not path.is_file():
        return _err(f"file not found: {raw_path}")

    if path.suffix.lower() not in EXTRACTORS:
        return _err(f"unsupported file type: {path.suffix}")

    try:
        fmt, raw_text = extract_document(path)
    except Exception as exc:
        return _err(f"{type(exc).__name__}: {exc}")

    cleaned, findings = strip_hidden(raw_text)
    payload = {
        "format": fmt,
        "byte_count": path.stat().st_size,
        "char_count": len(cleaned),
        "stripped_findings": len(findings),
        "text": cleaned,
        "findings": [
            {"label": f.label, "line_number": f.line_number, "evidence": f.evidence}
            for f in findings
        ],
    }
    return {"isError": False, "content": [{"type": "text", "text": json.dumps(payload)}]}


def _err(text: str) -> dict[str, Any]:
    return {"isError": True, "content": [{"type": "text", "text": text}]}


def build_server() -> BaseMCPServer:
    """Build a configured ``file_extractor`` MCP server."""
    server = BaseMCPServer(name="file_extractor")
    server.register(
        ToolSpec(
            name="extract_text",
            description=(
                "Extract cleaned text from a document at the given path. "
                "READ-ONLY server: no filesystem-write capability. Strips "
                "metadata, HTML comments, hidden-unicode, and base64 payloads "
                "before returning."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "redact_pii": {"type": "boolean"},
                },
                "required": ["path"],
            },
            handler=_extract_text,
        ),
    )
    return server


if __name__ == "__main__":
    build_server().run()
