# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.data.databricks_adapter

Purpose: parameterised query adapter for Databricks SQL. Lazy-imports
``databricks.sql`` so the testudo install does not require it; the optional
``[databricks]`` extra (declared in pyproject.toml) installs
``databricks-sql-connector``.

Inputs: a connection block (``server_hostname``, ``http_path``,
``access_token``); a parameterised query string; an optional list of
parameters.

Outputs: a ``QueryResult`` with the rows materialised as a list of dicts.

Assumptions: v0.1 supports Personal Access Token auth only; service
principal auth lands in v0.2. The free Databricks Community Edition is the
default demo target; the same adapter works against any Databricks SQL
warehouse with a valid PAT.

Failure modes: ``ImportError`` if the ``[databricks]`` extra was not
installed; ``databricks.sql.exc`` errors for connection or query failures.
"""

from __future__ import annotations

from typing import Any

from testudo.data.result import QueryResult


def query_databricks(
    connection: dict[str, Any],
    query: str,
    parameters: list[Any] | None = None,
) -> QueryResult:
    """Execute a parameterised query against a Databricks SQL warehouse."""
    try:
        from databricks import sql as dbx_sql
    except ImportError as exc:
        raise ImportError(
            'Databricks adapter requires the [databricks] extra: uv pip install -e ".[databricks]"'
        ) from exc

    required_keys = {"server_hostname", "http_path", "access_token"}
    missing = required_keys - connection.keys()
    if missing:
        raise ValueError(f"Databricks connection missing keys: {sorted(missing)}")

    with dbx_sql.connect(
        server_hostname=connection["server_hostname"],
        http_path=connection["http_path"],
        access_token=connection["access_token"],
    ) as conn:
        cursor = conn.cursor()
        cursor.execute(query, parameters or [])
        columns = [d[0] for d in cursor.description] if cursor.description else []
        raw_rows = cursor.fetchall()
        rows = [dict(zip(columns, row, strict=False)) for row in raw_rows]

    return QueryResult(
        rows=rows,
        columns=columns,
        row_count=len(rows),
        query=query,
        adapter="databricks",
        metadata={
            "server_hostname": connection["server_hostname"],
            "http_path": connection["http_path"],
        },
    )
