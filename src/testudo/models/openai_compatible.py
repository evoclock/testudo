# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.models.openai_compatible

Purpose: thin client for any OpenAI-compatible chat-completions endpoint.
Hosted: OpenAI, OpenRouter, and other API providers exposing
``POST {base_url}/chat/completions``. Local: Ollama's OpenAI-compatible
endpoint, LM Studio, vLLM, SGLang, llama.cpp ``llama-server``, and MLX
(``mlx_lm.server``).
Single ``openai_compatible_chat`` function plus a registered
``models.openai_compatible_chat`` tool. Every response is passed through
:func:`testudo.sanitisers.output.sanitise_output` before returning, so secrets,
PII, hidden-unicode, prompt injection, and OWASP / MCP threat markers are
caught at the model boundary.

Inputs: model name, prompt, optional system prompt, optional base URL,
optional API key (resolved from the environment when omitted), optional
temperature, optional max tokens, optional timeout, optional client (for
test injection).

Outputs: the same sanitiser-decision dict shape as ``ollama_chat`` so
downstream steps and the UI treat both adapters identically.

Assumptions: the endpoint speaks the OpenAI chat-completions JSON dialect.
Streaming, tool-calling, and structured outputs are deferred.

Failure modes: connection or HTTP errors propagate as ``RuntimeError`` with
a short cause; the orchestrator captures these as ``StepResult.error`` so
downstream steps can decide whether to continue. The API key is never logged
and never returned in the result dict.

References:

- OpenAI chat-completions API: https://platform.openai.com/docs/api-reference/chat
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from testudo.sanitisers.output import sanitise_output

DEFAULT_BASE_URL = os.environ.get("TESTUDO_OPENAI_BASE_URL", "https://api.openai.com/v1")
DEFAULT_API_KEY_ENV = "TESTUDO_OPENAI_API_KEY"
DEFAULT_TIMEOUT = 120.0


def _resolve_api_key(api_key: str | None) -> str:
    """Return the caller-supplied key or the one from the environment.

    An explicit empty string disables authentication entirely (local
    servers such as llama.cpp often run without keys).
    """
    if api_key is not None:
        return api_key
    return os.environ.get(DEFAULT_API_KEY_ENV, "")


def openai_compatible_chat(
    *,
    model: str,
    prompt: str,
    system: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    temperature: float = 0.0,
    max_tokens: int | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """Call an OpenAI-compatible chat endpoint and return a sanitised result.

    ``client`` is provided so tests can inject ``httpx.MockTransport``.
    Production callers pass it as ``None`` and the function constructs its
    own client.
    """
    url = (base_url or DEFAULT_BASE_URL).rstrip("/")
    messages: list[dict[str, str]] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
    }
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens

    headers = {}
    key = _resolve_api_key(api_key)
    if key:
        headers["Authorization"] = f"Bearer {key}"

    owns_client = client is None
    http = client or httpx.Client(timeout=timeout)
    try:
        response = http.post(f"{url}/chat/completions", json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
    except httpx.HTTPError as exc:
        raise RuntimeError(f"OpenAI-compatible call failed: {exc}") from exc
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
    """Return the assistant message content from a chat-completions response."""
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0]
    if not isinstance(first, dict):
        return ""
    message = first.get("message")
    if isinstance(message, dict):
        return str(message.get("content", ""))
    # Some gateways return a bare text field (legacy completions shape).
    text = first.get("text")
    if isinstance(text, str):
        return text
    return ""
