"""
Module: testudo.data.result

Purpose: ``QueryResult`` dataclass returned by every data adapter. Carries the
result rows (each as a dict keyed by column), the column list, the row count,
and the executed query string for the audit trail.

Inputs: constructor arguments built by data adapter implementations.

Outputs: a frozen ``QueryResult`` plus a ``to_dict`` for JSON-serialisable
workflow consumption.

Assumptions: row values are JSON-compatible scalars (datetimes are coerced
to ISO 8601 strings by the adapter where needed).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class QueryResult:
    """Outcome of a parameterised data-adapter query."""

    rows: list[dict[str, Any]]
    columns: list[str]
    row_count: int
    query: str
    adapter: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rows": list(self.rows),
            "columns": list(self.columns),
            "row_count": self.row_count,
            "query": self.query,
            "adapter": self.adapter,
            "metadata": dict(self.metadata),
        }
