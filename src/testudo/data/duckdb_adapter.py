# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.data.duckdb_adapter

Purpose: parameterised query adapter for DuckDB. v0.1 default for the demo
path because it has no daemon, no auth, and ships with the testudo package
as a hard dependency.

Inputs: a database path (or ``":memory:"``); a parameterised query string;
an optional list of parameters.

Outputs: a ``QueryResult`` with the rows materialised as a list of dicts.

Assumptions: the query is already authored as parameterised; the adapter
does not interpolate user input into the SQL string. Callers needing
schema introspection or DDL should use a separate code path in v0.2.

Failure modes: ``duckdb.Error`` subclasses for SQL errors (propagated);
``FileNotFoundError`` for non-``:memory:`` paths that do not exist.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import duckdb

from testudo.data.result import QueryResult


def query_duckdb(
    database_path: Path | str,
    query: str,
    parameters: list[Any] | None = None,
) -> QueryResult:
    """Execute a parameterised query against a DuckDB database."""
    db_str = str(database_path)
    if db_str != ":memory:" and not Path(db_str).exists():
        raise FileNotFoundError(f"DuckDB database not found: {db_str}")

    conn = duckdb.connect(db_str)
    try:
        cursor = conn.execute(query, parameters or [])
        columns = [d[0] for d in cursor.description] if cursor.description else []
        raw_rows = cursor.fetchall()
        rows = [dict(zip(columns, row, strict=False)) for row in raw_rows]
    finally:
        conn.close()

    return QueryResult(
        rows=rows,
        columns=columns,
        row_count=len(rows),
        query=query,
        adapter="duckdb",
        metadata={"database": db_str},
    )
