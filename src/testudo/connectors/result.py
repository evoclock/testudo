"""
Module: testudo.connectors.result

Purpose: ``StagedInput`` dataclass returned by every connector. Carries the
content, an inferred format hint, the original source URI, byte count, and a
metadata dict for provenance information that flows into the audit log.

Inputs: constructor arguments built by the connector functions.

Outputs: a frozen ``StagedInput`` plus a ``to_dict`` for JSON-serialisable
workflow consumption.

Assumptions: v0.1 ships text-only payloads; binary support is deferred to v0.2
when a `bytes_content` channel will be added alongside the text one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class StagedInput:
    """A retrieved input ready for downstream workflow consumption."""

    content: str
    format: str
    source: str
    size_bytes: int
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "content": self.content,
            "format": self.format,
            "source": self.source,
            "size_bytes": self.size_bytes,
            "metadata": dict(self.metadata),
        }
