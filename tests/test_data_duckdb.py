"""Tests for ``testudo.data.duckdb_adapter``: in-memory parameterised queries."""

from __future__ import annotations

from pathlib import Path

import pytest

from testudo.data.duckdb_adapter import query_duckdb


def test_query_duckdb_returns_rows_for_in_memory_query() -> None:
    result = query_duckdb(":memory:", "SELECT 1 AS a, 2 AS b")
    assert result.rows == [{"a": 1, "b": 2}]
    assert result.columns == ["a", "b"]
    assert result.row_count == 1
    assert result.adapter == "duckdb"
    assert result.query == "SELECT 1 AS a, 2 AS b"


def test_query_duckdb_supports_parameters() -> None:
    result = query_duckdb(":memory:", "SELECT ? AS x, ? AS y", parameters=["foo", 42])
    assert result.rows == [{"x": "foo", "y": 42}]


def test_query_duckdb_returns_empty_rows_for_no_match() -> None:
    result = query_duckdb(
        ":memory:",
        "SELECT * FROM (VALUES (1), (2)) AS t(n) WHERE n > 100",
    )
    assert result.rows == []
    assert result.row_count == 0


def test_query_duckdb_rejects_missing_database_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        query_duckdb(tmp_path / "missing.duckdb", "SELECT 1")


def test_query_duckdb_against_persisted_database(tmp_path: Path) -> None:
    import duckdb

    db_path = tmp_path / "demo.duckdb"
    conn = duckdb.connect(str(db_path))
    conn.execute("CREATE TABLE attendees (name TEXT, role TEXT)")
    conn.execute("INSERT INTO attendees VALUES ('Julen', 'Tech Lead')")
    conn.close()

    result = query_duckdb(db_path, "SELECT name, role FROM attendees")
    assert result.rows == [{"name": "Julen", "role": "Tech Lead"}]


def test_query_duckdb_to_dict_round_trip() -> None:
    result = query_duckdb(":memory:", "SELECT 1 AS x")
    payload = result.to_dict()
    assert payload["rows"] == [{"x": 1}]
    assert payload["columns"] == ["x"]
    assert payload["adapter"] == "duckdb"
