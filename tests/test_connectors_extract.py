# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for ``testudo.connectors.extract`` and the ``connectors.extract_document`` tool."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from testudo.connectors.extract import (
    EXTRACTORS,
    extract_document,
    extract_html,
    extract_json,
    extract_text_file,
)


def test_extract_text_file_returns_content(tmp_path: Path) -> None:
    target = tmp_path / "note.md"
    target.write_text("# hi\nbody")
    assert extract_text_file(target) == "# hi\nbody"


def test_extract_html_drops_tags_and_comments(tmp_path: Path) -> None:
    target = tmp_path / "page.html"
    target.write_text(
        "<html><head><style>x</style></head><body>"
        "<!-- secret --><script>alert(1)</script>"
        "<p>Visible content</p></body></html>"
    )
    out = extract_html(target)
    assert "Visible content" in out
    assert "secret" not in out
    assert "alert" not in out
    assert "<p>" not in out


def test_extract_json_pretty_prints(tmp_path: Path) -> None:
    target = tmp_path / "data.json"
    target.write_text('{"b": 2, "a": 1}')
    out = extract_json(target)
    parsed = json.loads(out)
    assert parsed == {"a": 1, "b": 2}


def test_extract_document_dispatches_on_suffix(tmp_path: Path) -> None:
    target = tmp_path / "doc.md"
    target.write_text("hello")
    fmt, text = extract_document(target)
    assert fmt == ".md"
    assert text == "hello"


def test_extract_document_rejects_unknown_suffix(tmp_path: Path) -> None:
    target = tmp_path / "binary.bin"
    target.write_bytes(b"\x00\x01")
    with pytest.raises(ValueError, match="Unsupported document format"):
        extract_document(target)


def test_extractors_table_includes_common_formats() -> None:
    for suffix in (
        ".txt",
        ".md",
        ".log",
        ".csv",
        ".tsv",
        ".json",
        ".html",
        ".htm",
        ".pptx",
        ".pdf",
        ".docx",
    ):
        assert suffix in EXTRACTORS, suffix


def test_extract_document_tool_strips_hidden_payloads(tmp_path: Path) -> None:
    from testudo import _loaded  # noqa: F401
    from testudo.orchestrator.context import StepContext
    from testudo.orchestrator.registry import DEFAULT_REGISTRY

    target = tmp_path / "doc.md"
    target.write_text("before​after")
    from testudo.permissions import Permissions

    ctx = StepContext(
        permissions=Permissions(),
        audit=None,
        run_id="t",
        workflow_name="wf",
        step_id="extract",
    )
    result = DEFAULT_REGISTRY.resolve("connectors.extract_document")(ctx, path=str(target))

    assert "​" not in result["content"]
    assert result["format"] == ".md"
    assert result["stripped_findings"] >= 1


def test_extract_document_tool_missing_file_raises(tmp_path: Path) -> None:
    from testudo import _loaded  # noqa: F401
    from testudo.orchestrator.context import StepContext
    from testudo.orchestrator.registry import DEFAULT_REGISTRY
    from testudo.permissions import Permissions

    ctx = StepContext(
        permissions=Permissions(),
        audit=None,
        run_id="t",
        workflow_name="wf",
        step_id="extract",
    )
    with pytest.raises(FileNotFoundError):
        DEFAULT_REGISTRY.resolve("connectors.extract_document")(
            ctx, path=str(tmp_path / "missing.pdf")
        )
