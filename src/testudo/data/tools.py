# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

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
from testudo.seats.credentials import get_provider_key


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
    query: str,
    connection: dict[str, Any] | None = None,
    parameters: list[Any] | None = None,
) -> dict[str, Any]:
    """Run a parameterised query against a Databricks SQL warehouse.

    ``connection`` is optional. If absent, non-sensitive endpoint settings
    come from ``DATABRICKS_SERVER_HOSTNAME`` / ``DATABRICKS_HTTP_PATH`` and
    the hosted access token comes from the platform credential store.
    """
    import os

    if connection is None:
        try:
            connection = {
                "server_hostname": os.environ["DATABRICKS_SERVER_HOSTNAME"],
                "http_path": os.environ["DATABRICKS_HTTP_PATH"],
                "access_token": get_provider_key("databricks"),
            }
        except KeyError as exc:
            raise RuntimeError("databricks-endpoint-config-missing") from exc
        if not connection["access_token"]:
            raise RuntimeError("databricks-credential-missing")

    return query_databricks(connection, query, parameters).to_dict()
