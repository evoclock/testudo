# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Testudo data package.

Purpose: parameterised query adapters. v0.1 default is DuckDB (no daemon,
no auth, hard dependency); the Databricks adapter is available behind the
``[databricks]`` extra and uses the same ``QueryResult`` contract.

Inputs: a connection specification plus a parameterised query.

Outputs: a ``QueryResult`` with rows materialised as a list of dicts plus
the executed query for the audit trail.

Side effect: importing this package registers ``data.duckdb_query`` and
``data.databricks_query`` in the orchestrator's ``DEFAULT_REGISTRY``.
"""

from testudo.data import tools  # noqa: F401  - registers data adapters
from testudo.data.databricks_adapter import query_databricks
from testudo.data.duckdb_adapter import query_duckdb
from testudo.data.result import QueryResult

__all__ = [
    "QueryResult",
    "query_databricks",
    "query_duckdb",
]
