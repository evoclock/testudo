"""
Module: testudo.models.tools

Purpose: register model-adapter functions as orchestrator tools. Side effect
of importing: every tool below appears in the orchestrator's
``DEFAULT_REGISTRY``.
"""

from __future__ import annotations

from typing import Any

from testudo.models.ollama import ollama_chat
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
