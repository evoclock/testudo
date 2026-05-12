"""
Module: testudo.orchestrator.loader

Purpose: load a workflow from disk (JSON or YAML) and produce the canonical
``Workflow`` plus the resolved ``Permissions`` and ``IsolationProfile`` for a
run.

Inputs: a path to ``workflow.json`` or ``workflow.yaml``; a ``Workflow`` for
the helper resolvers.

Outputs: a ``Workflow`` model from ``load_workflow``; a ``Permissions`` from
``resolve_permissions``; an ``IsolationProfile`` from ``resolve_isolation``.

Assumptions: file extension determines format (``.json`` vs ``.yaml``/``.yml``).
JSON is the v0.1 default; YAML is supported as a convenience because hand-written
workflow files are easier to read.

Failure modes: ``FileNotFoundError`` on missing file; ``json.JSONDecodeError`` or
``yaml.YAMLError`` on parse failure; Pydantic ``ValidationError`` on schema
mismatch (re-raised by ``Workflow.model_validate``).
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from testudo.orchestrator.workflow import Workflow
from testudo.permissions import Permissions, load_permissions
from testudo.runtime.isolation import IsolationProfile, load_isolation


def load_workflow(path: Path) -> Workflow:
    """Load and parse a workflow file (JSON or YAML)."""
    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw) if path.suffix in (".yaml", ".yml") else json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"Workflow file must contain a top-level object: {path}")
    return Workflow.model_validate(data)


def resolve_permissions(workflow: Workflow) -> Permissions:
    """Return the effective ``Permissions`` for a workflow."""
    return load_permissions(workflow.permissions)


def resolve_isolation(workflow: Workflow) -> IsolationProfile:
    """Return the effective ``IsolationProfile`` for a workflow."""
    return load_isolation(workflow.isolation)
