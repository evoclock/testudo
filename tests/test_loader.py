"""Tests for ``testudo.orchestrator.loader``: workflow loading and resolution."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from testudo.orchestrator.loader import (
    load_workflow,
    resolve_isolation,
    resolve_permissions,
)
from testudo.permissions import Permissions
from testudo.runtime.isolation import IsolationProfile

# ----------------------------------------------------------------------------
# load_workflow
# ----------------------------------------------------------------------------


def test_load_workflow_from_json(tmp_path: Path) -> None:
    spec = {
        "name": "demo",
        "steps": [{"id": "a", "uses": "noop"}],
    }
    path = tmp_path / "workflow.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    wf = load_workflow(path)
    assert wf.name == "demo"
    assert wf.steps[0].id == "a"


def test_load_workflow_from_yaml(tmp_path: Path) -> None:
    yaml_text = """\
name: demo
steps:
  - id: a
    uses: noop
"""
    path = tmp_path / "workflow.yaml"
    path.write_text(yaml_text, encoding="utf-8")
    wf = load_workflow(path)
    assert wf.name == "demo"


def test_load_workflow_rejects_non_object_root(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ValueError, match="top-level object"):
        load_workflow(path)


def test_load_workflow_propagates_validation_error(tmp_path: Path) -> None:
    path = tmp_path / "missing-name.json"
    path.write_text(json.dumps({"steps": []}), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_workflow(path)


# ----------------------------------------------------------------------------
# resolve_permissions / resolve_isolation
# ----------------------------------------------------------------------------


def test_resolve_permissions_default_when_block_missing(tmp_path: Path) -> None:
    path = tmp_path / "wf.json"
    path.write_text(
        json.dumps({"name": "demo", "steps": [{"id": "a", "uses": "noop"}]}),
        encoding="utf-8",
    )
    wf = load_workflow(path)
    assert resolve_permissions(wf) == Permissions()


def test_resolve_permissions_from_workflow_block(tmp_path: Path) -> None:
    path = tmp_path / "wf.json"
    path.write_text(
        json.dumps(
            {
                "name": "demo",
                "steps": [{"id": "a", "uses": "noop"}],
                "permissions": {
                    "filesystem": {"read": ["/in"], "write": ["/out"]},
                    "network": {"egress": []},
                    "process": {"spawn": False},
                },
            }
        ),
        encoding="utf-8",
    )
    wf = load_workflow(path)
    perms = resolve_permissions(wf)
    assert perms.filesystem.read == ("/in",)
    assert perms.filesystem.write == ("/out",)


def test_resolve_isolation_default_when_block_missing(tmp_path: Path) -> None:
    path = tmp_path / "wf.json"
    path.write_text(
        json.dumps({"name": "demo", "steps": [{"id": "a", "uses": "noop"}]}),
        encoding="utf-8",
    )
    wf = load_workflow(path)
    assert resolve_isolation(wf) == IsolationProfile()


def test_resolve_isolation_from_workflow_block(tmp_path: Path) -> None:
    path = tmp_path / "wf.json"
    path.write_text(
        json.dumps(
            {
                "name": "demo",
                "steps": [{"id": "a", "uses": "noop"}],
                "isolation": {"memory": "4g", "cpu": "2.0"},
            }
        ),
        encoding="utf-8",
    )
    wf = load_workflow(path)
    iso = resolve_isolation(wf)
    assert iso.memory == "4g"
    assert iso.cpu == "2.0"
