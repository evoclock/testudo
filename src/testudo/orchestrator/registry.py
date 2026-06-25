# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.orchestrator.registry

Purpose: tool registry. Maps a workflow's ``uses:`` string (e.g.
``"connectors.local_file"``) to a callable implementation. Registration is
explicit via the ``register_tool`` decorator; double-registration raises so
collisions are caught early.

Inputs: tool name (string) and a callable; lookup by name.

Outputs: the registered callable from ``resolve``.

Assumptions: tool callables follow the Testudo signature
``def tool(ctx: StepContext, **kwargs) -> Any``. Registration normally happens
at import time when the tool's package is loaded by the executor or its host
(in v0.1, the orchestrator's ``__init__`` imports ``testudo.orchestrator.tools``
to seed the default registry with the ``noop`` tool).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

T = TypeVar("T", bound=Callable[..., Any])


class ToolRegistry:
    """Registry mapping ``uses:`` strings to callable implementations."""

    def __init__(self) -> None:
        self._tools: dict[str, Callable[..., Any]] = {}

    def register(self, name: str) -> Callable[[T], T]:
        """Decorator: register a callable under ``name``."""

        def decorator(fn: T) -> T:
            if name in self._tools:
                raise ValueError(f"Tool already registered: {name!r}")
            self._tools[name] = fn
            return fn

        return decorator

    def resolve(self, name: str) -> Callable[..., Any]:
        """Return the callable registered under ``name``."""
        if name not in self._tools:
            raise KeyError(f"Tool not registered: {name!r}")
        return self._tools[name]

    def names(self) -> list[str]:
        """Return the sorted list of registered tool names."""
        return sorted(self._tools.keys())

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)


# The default global registry. Tools register here at import time.
DEFAULT_REGISTRY = ToolRegistry()


def register_tool(name: str) -> Callable[[T], T]:
    """Convenience: register a tool in the default registry."""
    return DEFAULT_REGISTRY.register(name)
