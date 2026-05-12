"""Tests for ``testudo.connectors.local``: file reading, size cap, format."""

from __future__ import annotations

from pathlib import Path

import pytest

from testudo.connectors.local import fetch_local


def test_fetch_local_reads_text_file(tmp_path: Path) -> None:
    p = tmp_path / "x.txt"
    p.write_text("hello", encoding="utf-8")
    staged = fetch_local(p)
    assert staged.content == "hello"
    assert staged.format == "text"
    assert staged.size_bytes == 5
    assert staged.source == str(p)


def test_fetch_local_infers_json_format(tmp_path: Path) -> None:
    p = tmp_path / "data.json"
    p.write_text("{}", encoding="utf-8")
    assert fetch_local(p).format == "json"


def test_fetch_local_infers_markdown_for_md_extension(tmp_path: Path) -> None:
    p = tmp_path / "doc.md"
    p.write_text("# hi", encoding="utf-8")
    assert fetch_local(p).format == "markdown"


def test_fetch_local_raises_on_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        fetch_local(tmp_path / "ghost.txt")


def test_fetch_local_raises_when_oversize(tmp_path: Path) -> None:
    p = tmp_path / "big.txt"
    p.write_bytes(b"x" * 100)
    with pytest.raises(ValueError, match="too large"):
        fetch_local(p, max_bytes=10)


def test_fetch_local_includes_mtime_metadata(tmp_path: Path) -> None:
    p = tmp_path / "x.txt"
    p.write_text("ok", encoding="utf-8")
    staged = fetch_local(p)
    assert "mtime" in staged.metadata
    assert isinstance(staged.metadata["mtime"], float)
