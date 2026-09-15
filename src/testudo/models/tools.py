# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.models.tools

Purpose: register model-adapter functions as orchestrator tools. Side effect
of importing: every tool below appears in the orchestrator's
``DEFAULT_REGISTRY``.
"""

from __future__ import annotations

from typing import Any

from testudo.models.ollama import ollama_chat
from testudo.models.openai_compatible import openai_compatible_chat
from testudo.orchestrator.context import StepContext
from testudo.orchestrator.registry import register_tool


@register_tool("models.ollama_chat")
def ollama_chat_tool(
    _ctx: StepContext,
    *,
    model: str,
    prompt: str,
    system: str | None = None,
    base_url: str | None = None,
    temperature: float = 0.0,
    timeout: float = 120.0,
) -> dict[str, Any]:
    """Call an Ollama-served model. Response is sanitised before return.

    Example workflow step::

        {
          "id": "summarise",
          "uses": "models.ollama_chat",
          "needs": ["extract"],
          "with": {
            "model": "minimax-m2.5",
            "prompt": "Summarise: ${steps.extract.content}",
            "system": "You are a careful, factual summariser."
          }
        }
    """
    return ollama_chat(
        model=model,
        prompt=prompt,
        system=system,
        base_url=base_url,
        temperature=temperature,
        timeout=timeout,
    )


@register_tool("models.openai_compatible_chat")
def openai_compatible_chat_tool(
    _ctx: StepContext,
    *,
    model: str,
    prompt: str,
    system: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    temperature: float = 0.0,
    max_tokens: int | None = None,
    timeout: float = 120.0,
) -> dict[str, Any]:
    """Call an OpenAI-compatible chat endpoint. Response is sanitised before return.

    Covers OpenAI, LM Studio, vLLM, llama.cpp server, OpenRouter, and any
    provider exposing ``POST {base_url}/chat/completions``. The API key is
    resolved from ``TESTUDO_OPENAI_API_KEY`` when omitted; pass an empty
    string for keyless local servers.

    Example workflow step::

        {
          "id": "summarise",
          "uses": "models.openai_compatible_chat",
          "needs": ["extract"],
          "with": {
            "model": "gpt-4o-mini",
            "prompt": "Summarise: ${steps.extract.content}",
            "system": "You are a careful, factual summariser."
          }
        }
    """
    return openai_compatible_chat(
        model=model,
        prompt=prompt,
        system=system,
        base_url=base_url,
        api_key=api_key,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
    )
