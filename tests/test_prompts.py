# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for ``testudo.prompts``: PromptTemplate and PromptLibrary."""

from __future__ import annotations

from pathlib import Path

import pytest

from testudo.prompts import (
    PromptLibrary,
    PromptTemplate,
    assemble_prompt,
    load_template,
)

# ----------------------------------------------------------------------------
# PromptTemplate
# ----------------------------------------------------------------------------


def test_template_renders_simple_placeholders() -> None:
    t = PromptTemplate(text="Hello {{name}}!")
    assert t.render(name="Julen") == "Hello Julen!"


def test_template_renders_repeated_placeholder() -> None:
    t = PromptTemplate(text="{{x}} and {{x}} again")
    assert t.render(x="ok") == "ok and ok again"


def test_template_supports_internal_whitespace_in_placeholder() -> None:
    t = PromptTemplate(text="value: {{  name  }}")
    assert t.render(name="z") == "value: z"


def test_template_strict_raises_on_unresolved_placeholder() -> None:
    t = PromptTemplate(text="Hello {{name}}, {{role}}!")
    with pytest.raises(ValueError, match="Unresolved"):
        t.render(name="Julen")


def test_template_non_strict_leaves_unresolved_placeholders() -> None:
    t = PromptTemplate(text="Hello {{name}}, {{role}}!")
    out = t.render(strict=False, name="Julen")
    assert "Julen" in out
    assert "{{role}}" in out


def test_template_placeholders_returns_set_of_names() -> None:
    t = PromptTemplate(text="<a>{{alpha}}</a><b>{{beta}}</b><c>{{alpha}}</c>")
    assert t.placeholders() == {"alpha", "beta"}


# ----------------------------------------------------------------------------
# load_template / assemble_prompt
# ----------------------------------------------------------------------------


def test_load_template_reads_file(tmp_path: Path) -> None:
    p = tmp_path / "hello.xml"
    p.write_text("<x>{{name}}</x>", encoding="utf-8")
    t = load_template(p)
    assert t.text == "<x>{{name}}</x>"
    assert t.name == "hello"


def test_assemble_prompt_renders_in_one_call(tmp_path: Path) -> None:
    p = tmp_path / "greet.xml"
    p.write_text("<g>{{who}}</g>", encoding="utf-8")
    out = assemble_prompt(p, who="world")
    assert out == "<g>world</g>"


# ----------------------------------------------------------------------------
# PromptLibrary
# ----------------------------------------------------------------------------


@pytest.fixture
def library_root(tmp_path: Path) -> Path:
    (tmp_path / "alpha.xml").write_text("<a>{{x}}</a>", encoding="utf-8")
    (tmp_path / "beta.txt").write_text("text {{x}}", encoding="utf-8")
    (tmp_path / "gamma.md").write_text("md {{x}}", encoding="utf-8")
    (tmp_path / "ignored.json").write_text('{"not": "a template"}', encoding="utf-8")
    return tmp_path


def test_library_lists_templates_alphabetically(library_root: Path) -> None:
    lib = PromptLibrary(library_root)
    assert lib.list_templates() == ["alpha", "beta", "gamma"]


def test_library_get_returns_template_by_name(library_root: Path) -> None:
    lib = PromptLibrary(library_root)
    t = lib.get("alpha")
    assert t.text == "<a>{{x}}</a>"


def test_library_resolves_priority_extension_first(library_root: Path) -> None:
    # alpha exists as .xml; create a competing .md and confirm .xml wins
    (library_root / "alpha.md").write_text("md alpha", encoding="utf-8")
    lib = PromptLibrary(library_root)
    assert lib.get("alpha").text == "<a>{{x}}</a>"


def test_library_get_missing_raises(library_root: Path) -> None:
    lib = PromptLibrary(library_root)
    with pytest.raises(FileNotFoundError, match="ghost"):
        lib.get("ghost")


def test_library_init_missing_root_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        PromptLibrary(tmp_path / "does-not-exist")
