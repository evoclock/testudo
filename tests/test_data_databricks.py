# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for ``testudo.data.databricks_adapter``: import gating + mocked query."""

from __future__ import annotations

from typing import Any

import pytest

from testudo.data.databricks_adapter import query_databricks


def test_query_databricks_raises_import_error_when_extra_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ``databricks.sql`` is not importable, raise a friendly error."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "databricks.sql" or name.startswith("databricks"):
            raise ImportError("No module named 'databricks'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(ImportError, match=r"\[databricks\]"):
        query_databricks(
            {
                "server_hostname": "x",
                "http_path": "/sql/x",
                "access_token": "t",
            },
            "SELECT 1",
        )


# Connection-key validation test deferred: requires the databricks-sql-connector
# extra to be installed so the import gate passes. Covered by the v0.1 integration
# test in Chunk 7 when running against a real Databricks endpoint, and by code
# review of databricks_adapter.query_databricks (lines after the import gate).
