# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.mcp_servers.llm_response_capturer

Purpose: read-only MCP server that captures LLM tool-call output, runs the
output-side sanitiser, and emits a signed receipt the write-side MCP
server (:mod:`testudo.mcp_servers.file_writer`) will validate before
accepting any payload for disk-write.

Inputs: a ``capture_response`` tool call with ``model``, ``content``, and
optional ``meta``.

Outputs: a structured result containing the cleaned content, a list of
findings, the sanitiser decision, and an HMAC-signed receipt. The receipt
is a base64 token over ``run_id || content_sha256 || decision``; the
write-side server checks the signature against the per-run key before
accepting a write.

Assumptions: this server has NO filesystem-write capability. It does not
import :mod:`testudo.outputs.file` or the orchestrator's write-side
tools. Any attempt to invoke a write-side tool from this server is a
configuration bug, not a runtime denial.

References:

- User direction 2026-05-12: LLM responses come through a read-only MCP
  server, are sanitised, then handed to the read/write server.
- MCP presentation v4 slide 24 (policy as the safety boundary).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass

from testudo.mcp_servers.base import BaseMCPServer, ToolSpec
from testudo.sanitisers.output import sanitise_output

SIGNING_KEY_ENV = "TESTUDO_RECEIPT_KEY"


@dataclass(slots=True)
class Receipt:
    """HMAC-signed sanitisation receipt.

    The write-side server validates this before accepting any payload for
    disk-write; an unsigned or stale receipt is a hard rejection.
    """

    run_id: str
    content_sha256: str
    decision: str
    signature: str

    def to_dict(self) -> dict[str, str]:
        return {
            "run_id": self.run_id,
            "content_sha256": self.content_sha256,
            "decision": self.decision,
            "signature": self.signature,
        }


def issue_receipt(*, run_id: str, content: str, decision: str, key: bytes | None = None) -> Receipt:
    """Issue a fresh receipt for a sanitised content blob."""
    signing_key = key or _load_signing_key()
    sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    payload = f"{run_id}|{sha}|{decision}".encode()
    signature = base64.urlsafe_b64encode(
        hmac.new(signing_key, payload, hashlib.sha256).digest()
    ).decode()
    return Receipt(run_id=run_id, content_sha256=sha, decision=decision, signature=signature)


def verify_receipt(
    *,
    receipt: dict[str, str],
    content: str,
    key: bytes | None = None,
) -> bool:
    """Return True iff the receipt's signature matches the content + decision."""
    signing_key = key or _load_signing_key()
    sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    if receipt.get("content_sha256") != sha:
        return False
    payload = f"{receipt.get('run_id', '')}|{sha}|{receipt.get('decision', '')}".encode()
    expected = base64.urlsafe_b64encode(
        hmac.new(signing_key, payload, hashlib.sha256).digest()
    ).decode()
    return hmac.compare_digest(expected, receipt.get("signature", ""))


def _load_signing_key() -> bytes:
    """Load the per-run signing key from ``TESTUDO_RECEIPT_KEY``.

    The orchestrator generates a fresh key per workflow run and exports it
    to both the capturer and the writer subprocesses. Missing key in
    production is an exception; tests inject a known key directly.
    """
    raw = os.environ.get(SIGNING_KEY_ENV)
    if not raw:
        raise RuntimeError(
            f"{SIGNING_KEY_ENV} is not set; the orchestrator must export a "
            "per-run signing key before launching this server."
        )
    return raw.encode("utf-8")


def _capture_response(arguments: dict[str, object]) -> dict[str, object]:
    """``capture_response`` tool handler: sanitise + issue receipt."""
    content = arguments.get("content")
    run_id = arguments.get("run_id")
    if not isinstance(content, str) or not isinstance(run_id, str):
        return {
            "isError": True,
            "content": [{"type": "text", "text": "run_id and content are required strings"}],
        }

    result = sanitise_output(content)
    receipt = issue_receipt(run_id=run_id, content=result.content, decision=result.decision)

    payload = {
        "decision": result.decision,
        "content": result.content,
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": int(f.severity),
                "category": f.category,
                "label": f.label,
                "evidence": f.evidence,
                "line_number": f.line_number,
            }
            for f in result.findings
        ],
        "receipt": receipt.to_dict(),
    }
    return {
        "isError": False,
        "content": [{"type": "text", "text": json.dumps(payload)}],
    }


def build_server() -> BaseMCPServer:
    """Build a configured ``llm_response_capturer`` MCP server."""
    server = BaseMCPServer(name="llm_response_capturer")
    server.register(
        ToolSpec(
            name="capture_response",
            description=(
                "Sanitise an LLM tool-call response and issue a signed receipt. "
                "READ-ONLY server: no filesystem-write capability. The receipt "
                "must accompany any subsequent write request to the file_writer."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "run_id": {"type": "string"},
                    "content": {"type": "string"},
                    "model": {"type": "string"},
                    "meta": {"type": "object"},
                },
                "required": ["run_id", "content"],
            },
            handler=_capture_response,
        ),
    )
    return server


if __name__ == "__main__":
    build_server().run()
