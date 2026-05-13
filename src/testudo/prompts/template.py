"""
Module: testudo.prompts.template

Purpose: simple XML-shaped prompt template loader plus ``{{placeholder}}``
substitution. Pattern adopted from the benefits-extraction reference
architecture: templates are plain text in version control, edits do not
require redeployment, and there is no conditional logic in the assembler;
all branching stays in natural language inside ``<task>``.

Inputs: a template string or a path to a template file; a dict of
substitution variables.

Outputs: the assembled prompt string.

Assumptions: placeholders use the convention ``{{name}}`` (double curly
braces, no spaces). Substitution is plain string replacement; no escaping
or expression evaluation.

Failure modes: ``ValueError`` if a placeholder remains unsubstituted after
rendering and ``strict=True`` (default).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")


@dataclass(frozen=True, slots=True)
class PromptTemplate:
    """A loaded prompt template ready for ``{{placeholder}}`` substitution."""

    text: str
    name: str | None = None

    def placeholders(self) -> set[str]:
        """Return the set of placeholder names referenced in the template."""
        return set(_PLACEHOLDER_RE.findall(self.text))

    def render(self, *, strict: bool = True, **variables: object) -> str:
        """Render the template, substituting ``{{name}}`` placeholders.

        With ``strict=True`` (default), raises ``ValueError`` if any
        placeholder is not provided in ``variables``.
        """
        result = self.text
        for key, value in variables.items():
            replacement = str(value)

            def _replace(_m: re.Match[str], v: str = replacement) -> str:
                return v

            result = re.sub(
                r"\{\{\s*" + re.escape(key) + r"\s*\}\}",
                _replace,
                result,
            )
        if strict:
            unresolved = set(_PLACEHOLDER_RE.findall(result))
            if unresolved:
                raise ValueError(f"Unresolved placeholders: {sorted(unresolved)!r}")
        return result


def load_template(path: Path) -> PromptTemplate:
    """Load a template from disk."""
    return PromptTemplate(text=path.read_text(encoding="utf-8"), name=path.stem)


def assemble_prompt(path: Path, *, strict: bool = True, **variables: object) -> str:
    """Convenience: load a template and render with the given variables."""
    return load_template(path).render(strict=strict, **variables)
