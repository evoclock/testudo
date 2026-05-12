"""
Module: testudo.permissions.loader

Purpose: load a ``Permissions`` model from a workflow's ``permissions:`` dict
(as parsed from ``workflow.json`` or YAML). Returns a deny-by-default
``Permissions`` instance when the block is missing or empty.

Inputs: a dict, or ``None``.

Outputs: a ``Permissions`` instance.

Assumptions: dict structure matches the schema in ``docs/ARCHITECTURE.md``;
Pydantic raises ``ValidationError`` on unknown or malformed keys.
"""

from __future__ import annotations

from testudo.permissions.model import Permissions


def load_permissions(block: dict[str, object] | None) -> Permissions:
    """Return a ``Permissions`` instance from a workflow's ``permissions:`` block."""
    if not block:
        return Permissions()
    return Permissions.model_validate(block)
