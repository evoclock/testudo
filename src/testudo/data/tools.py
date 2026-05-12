"""
Module: testudo.data.tools

Purpose: register data adapters as orchestrator tools. Side effect of importing
this module: ``data.duckdb_query`` and ``data.databricks_query`` appear in the
orchestrator's ``DEFAULT_REGISTRY``.
"""

from __future__ import annotations

from typing import Any

from testudo.data.databricks_adapter import query_databricks
from testudo.data.duckdb_adapter import query_duckdb
from testudo.orchestrator.context import StepContext
from testudo.orchestrator.registry import register_tool


@register_tool("data.duckdb_query")
def duckdb_query_tool(
    _ctx: StepContext,
    *,
    database: str,
    query: str,
    parameters: list[Any] | None = None,
) -> dict[str, Any]:
    """Run a parameterised query against a DuckDB database."""
    return query_duckdb(database, query, parameters).to_dict()


@register_tool("data.databricks_query")
def databricks_query_tool(
    _ctx: StepContext,
    *,
    connection: dict[str, Any],
    query: str,
    parameters: list[Any] | None = None,
) -> dict[str, Any]:
    """Run a parameterised query against a Databricks SQL warehouse."""
    return query_databricks(connection, query, parameters).to_dict()
