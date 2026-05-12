"""
Module: testudo.prompts.library

Purpose: directory-scoped prompt library. Resolves a template by name (without
extension) by looking under a configured root directory. v0.1 supports
``.xml``, ``.txt``, and ``.md`` extensions in that priority order.

Inputs: a root directory of templates; a template name to look up.

Outputs: a ``PromptTemplate`` from ``get``; a sorted list of template names
from ``list_templates``.

Assumptions: every template's filename stem is its canonical name; collisions
across extensions resolve in the priority order above. Workflow authors
configure the library root via the workflow's ``isolation.prompt_dir`` (when
implemented in v0.2) or the orchestrator's default of ``./prompts``.

Failure modes: ``FileNotFoundError`` if the root directory does not exist or
no matching template is found.
"""

from __future__ import annotations

from pathlib import Path

from testudo.prompts.template import PromptTemplate, load_template

_EXTENSIONS_PRIORITY: tuple[str, ...] = (".xml", ".txt", ".md")


class PromptLibrary:
    """Look up templates in a directory by name."""

    def __init__(self, root: Path) -> None:
        if not root.is_dir():
            raise FileNotFoundError(f"Prompt library root not found: {root}")
        self.root = root

    def get(self, name: str) -> PromptTemplate:
        """Return the template registered under ``name``."""
        for ext in _EXTENSIONS_PRIORITY:
            candidate = self.root / f"{name}{ext}"
            if candidate.exists():
                return load_template(candidate)
        raise FileNotFoundError(f"Template not found: {name!r} (searched {self.root})")

    def list_templates(self) -> list[str]:
        """Return the sorted list of template names available in this library."""
        names: set[str] = set()
        for path in self.root.iterdir():
            if path.suffix in _EXTENSIONS_PRIORITY:
                names.add(path.stem)
        return sorted(names)
