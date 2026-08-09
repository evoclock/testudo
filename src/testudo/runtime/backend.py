"""Execution backend selection for Testudo runs."""

from __future__ import annotations

from enum import StrEnum


class ExecutionBackend(StrEnum):
    """Supported host execution boundaries."""

    MICROVM = "microvm"
    DOCKER = "docker"


def coerce_backend(value: ExecutionBackend | str) -> ExecutionBackend:
    """Parse a backend name and reject unknown or unsafe fallbacks."""
    if isinstance(value, ExecutionBackend):
        return value
    try:
        return ExecutionBackend(value)
    except ValueError as exc:
        raise ValueError(f"unsupported execution backend: {value!r}") from exc


__all__ = ["ExecutionBackend", "coerce_backend"]
