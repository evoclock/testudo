"""
Module: testudo.models.ollama

Purpose: thin client for an Ollama-served model (https://ollama.com). Single
``ollama_chat`` function plus a registered ``models.ollama_chat`` tool. Every
response is passed through :func:`testudo.sanitisers.output.sanitise_output`
before returning, so secrets, PII, hidden-unicode, prompt injection, and
OWASP / MCP threat markers are caught at the model boundary.

Inputs: model name, prompt, optional system prompt, optional base URL,
optional temperature, optional client (for test injection).

Outputs: a dict with the sanitiser decision, the cleaned content, findings,
the raw / sanitised lengths, and the model name.

Assumptions: Ollama is reachable at the configured base URL. v0.1.5 calls
the ``/api/chat`` endpoint with ``stream: false``; streaming and the
``/api/generate`` endpoint are deferred to v0.2.

Failure modes: connection or HTTP errors propagate as ``RuntimeError`` with
a short cause; the orchestrator captures these as ``StepResult.error`` so
downstream steps can decide whether to continue.

References:

- Ollama HTTP API: https://github.com/ollama/ollama/blob/main/docs/api.md
- MCP presentation v4 slide 25 (output-side sanitisation invariant).
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from testudo.sanitisers.output import sanitise_output

DEFAULT_BASE_URL = os.environ.get("TESTUDO_OLLAMA_URL", "http://localhost:11434")
DEFAULT_TIMEOUT = 120.0


def ollama_chat(
    *,
    model: str,
    prompt: str,
    system: str | None = None,
    base_url: str | None = None,
    temperature: float = 0.0,
    timeout: float = DEFAULT_TIMEOUT,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """Call an Ollama-served chat model and return a sanitised result.

    ``client`` is provided so tests can inject ``httpx.MockTransport``.
    Production callers pass it as ``None`` and the function constructs its
    own client.
    """
    url = (base_url or DEFAULT_BASE_URL).rstrip("/")
    messages: list[dict[str, str]] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": temperature},
    }

    owns_client = client is None
    http = client or httpx.Client(timeout=timeout)
    try:
        response = http.post(f"{url}/api/chat", json=payload)
        response.raise_for_status()
        data = response.json()
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Ollama call failed: {exc}") from exc
    finally:
        if owns_client:
            http.close()

    raw = _extract_content(data)
    result = sanitise_output(raw)
    return {
        "model": model,
        "decision": result.decision,
        "content": result.content,
        "raw_length": len(raw),
        "sanitised_length": len(result.content),
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
    }


def _extract_content(data: dict[str, Any]) -> str:
    """Return the assistant message content from an Ollama /api/chat response.

    Tolerates the two response shapes Ollama has shipped: ``{"message":
    {"content": "..."}}`` (current) and ``{"response": "..."}`` (legacy /api/generate).
    """
    if isinstance(data.get("message"), dict):
        return str(data["message"].get("content", ""))
    response_value = data.get("response")
    if isinstance(response_value, str):
        return response_value
    return ""
