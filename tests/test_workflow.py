"""Tests for ``testudo.orchestrator.workflow``: Workflow, Step, WorkflowInput."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from testudo.orchestrator.workflow import Step, Workflow, WorkflowInput

# ----------------------------------------------------------------------------
# Step
# ----------------------------------------------------------------------------


def test_step_minimal_required_fields() -> None:
    step = Step(id="ingest", uses="connectors.local_file")
    assert step.id == "ingest"
    assert step.uses == "connectors.local_file"
    assert step.needs == ()
    assert step.with_ == {}
    assert step.when is None


def test_step_accepts_with_alias_from_workflow_json() -> None:
    raw = {"id": "ingest", "uses": "noop", "with": {"path": "/tmp/x"}}
    step = Step.model_validate(raw)
    assert step.with_ == {"path": "/tmp/x"}


def test_step_is_frozen() -> None:
    step = Step(id="a", uses="noop")
    with pytest.raises(ValidationError):
        step.uses = "evil"  # type: ignore[misc]


def test_step_ignores_unknown_fields_for_hillstar_compat() -> None:
    raw = {"id": "a", "uses": "noop", "future_hillstar_field": True}
    step = Step.model_validate(raw)
    assert step.id == "a"


# ----------------------------------------------------------------------------
# WorkflowInput
# ----------------------------------------------------------------------------


def test_workflow_input_defaults() -> None:
    wi = WorkflowInput(type="file")
    assert wi.required is True
    assert wi.format is None
    assert wi.default is None


def test_workflow_input_rejects_unknown_keys() -> None:
    with pytest.raises(ValidationError):
        WorkflowInput.model_validate({"type": "file", "spurious": True})


# ----------------------------------------------------------------------------
# Workflow
# ----------------------------------------------------------------------------


def test_workflow_minimal() -> None:
    wf = Workflow(name="demo", steps=(Step(id="a", uses="noop"),))
    assert wf.name == "demo"
    assert len(wf.steps) == 1


def test_workflow_full_round_trip_via_dict() -> None:
    raw = {
        "name": "meeting-debrief",
        "description": "Demo",
        "inputs": {"transcript": {"type": "file", "required": True}},
        "steps": [
            {"id": "ingest", "uses": "noop", "with": {"path": "${inputs.transcript}"}},
            {"id": "answer", "uses": "noop", "needs": ["ingest"]},
        ],
        "permissions": {"filesystem": {"read": ["/in"], "write": ["/out"]}},
        "isolation": {"image": "testudo:0.1", "memory": "1g"},
    }
    wf = Workflow.model_validate(raw)
    assert wf.name == "meeting-debrief"
    assert wf.steps[0].with_ == {"path": "${inputs.transcript}"}
    assert wf.steps[1].needs == ("ingest",)
    assert wf.permissions == {"filesystem": {"read": ["/in"], "write": ["/out"]}}
    assert wf.isolation == {"image": "testudo:0.1", "memory": "1g"}
