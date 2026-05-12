"""Tests for ``testudo.orchestrator.executor``: ordering, references, when, errors."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from testudo.audit import AuditLog
from testudo.orchestrator.context import StepContext
from testudo.orchestrator.executor import Executor, WorkflowError
from testudo.orchestrator.registry import ToolRegistry
from testudo.orchestrator.workflow import Step, Workflow
from testudo.permissions import Permissions


@pytest.fixture
def reg() -> ToolRegistry:
    """Fresh registry seeded with test tools."""
    r = ToolRegistry()

    @r.register("echo")
    def echo(_ctx: StepContext, **kwargs: Any) -> dict[str, Any]:
        return {"echoed": dict(kwargs)}

    @r.register("flagger")
    def flagger(_ctx: StepContext, *, on: bool = True) -> dict[str, bool]:
        return {"on": on}

    @r.register("kaboom")
    def kaboom(_ctx: StepContext) -> None:
        raise RuntimeError("intentional failure")

    return r


@pytest.fixture
def perms() -> Permissions:
    return Permissions()


# ----------------------------------------------------------------------------
# Topological ordering
# ----------------------------------------------------------------------------


def test_executor_runs_steps_in_dependency_order(reg: ToolRegistry, perms: Permissions) -> None:
    workflow = Workflow(
        name="demo",
        steps=(
            Step(id="b", uses="echo", needs=("a",)),
            Step(id="a", uses="echo"),
            Step(id="c", uses="echo", needs=("b",)),
        ),
    )
    results = Executor(registry=reg).run(workflow, inputs={}, permissions=perms)
    assert set(results) == {"a", "b", "c"}
    assert all(r.error is None and not r.skipped for r in results.values())


def test_executor_detects_cycles(reg: ToolRegistry, perms: Permissions) -> None:
    workflow = Workflow(
        name="demo",
        steps=(
            Step(id="a", uses="echo", needs=("b",)),
            Step(id="b", uses="echo", needs=("a",)),
        ),
    )
    with pytest.raises(WorkflowError, match="Cycle"):
        Executor(registry=reg).run(workflow, inputs={}, permissions=perms)


def test_executor_detects_unknown_needs(reg: ToolRegistry, perms: Permissions) -> None:
    workflow = Workflow(
        name="demo",
        steps=(Step(id="a", uses="echo", needs=("ghost",)),),
    )
    with pytest.raises(WorkflowError, match="Unknown step ID"):
        Executor(registry=reg).run(workflow, inputs={}, permissions=perms)


# ----------------------------------------------------------------------------
# Reference resolution
# ----------------------------------------------------------------------------


def test_executor_resolves_input_references(reg: ToolRegistry, perms: Permissions) -> None:
    workflow = Workflow(
        name="demo",
        steps=(Step(id="a", uses="echo", with_={"name": "${inputs.who}"}),),
    )
    results = Executor(registry=reg).run(workflow, inputs={"who": "Julen"}, permissions=perms)
    assert results["a"].output == {"echoed": {"name": "Julen"}}


def test_executor_resolves_step_output_references(reg: ToolRegistry, perms: Permissions) -> None:
    workflow = Workflow(
        name="demo",
        steps=(
            Step(id="a", uses="echo", with_={"v": 42}),
            Step(
                id="b",
                uses="echo",
                needs=("a",),
                with_={"prev": "${steps.a.echoed.v}"},
            ),
        ),
    )
    results = Executor(registry=reg).run(workflow, inputs={}, permissions=perms)
    assert results["b"].output == {"echoed": {"prev": 42}}


def test_executor_records_reference_failure(reg: ToolRegistry, perms: Permissions) -> None:
    workflow = Workflow(
        name="demo",
        steps=(Step(id="a", uses="echo", with_={"v": "${inputs.missing}"}),),
    )
    results = Executor(registry=reg).run(workflow, inputs={}, permissions=perms)
    assert results["a"].error is not None
    assert "missing" in results["a"].error


# ----------------------------------------------------------------------------
# when: predicate
# ----------------------------------------------------------------------------


def test_executor_skips_step_when_predicate_false(reg: ToolRegistry, perms: Permissions) -> None:
    workflow = Workflow(
        name="demo",
        steps=(
            Step(id="flag", uses="flagger", with_={"on": False}),
            Step(
                id="conditional",
                uses="echo",
                needs=("flag",),
                when="${steps.flag.on}",
            ),
        ),
    )
    results = Executor(registry=reg).run(workflow, inputs={}, permissions=perms)
    assert results["flag"].error is None
    assert results["conditional"].skipped is True


def test_executor_runs_step_when_predicate_true(reg: ToolRegistry, perms: Permissions) -> None:
    workflow = Workflow(
        name="demo",
        steps=(
            Step(id="flag", uses="flagger", with_={"on": True}),
            Step(
                id="conditional",
                uses="echo",
                needs=("flag",),
                when="${steps.flag.on}",
            ),
        ),
    )
    results = Executor(registry=reg).run(workflow, inputs={}, permissions=perms)
    assert results["conditional"].skipped is False


def test_executor_rejects_non_ref_when_expression(reg: ToolRegistry, perms: Permissions) -> None:
    workflow = Workflow(
        name="demo",
        steps=(Step(id="a", uses="echo", when="True or False"),),
    )
    results = Executor(registry=reg).run(workflow, inputs={}, permissions=perms)
    assert results["a"].error is not None
    assert "v0.1" in results["a"].error


# ----------------------------------------------------------------------------
# Errors and audit
# ----------------------------------------------------------------------------


def test_executor_records_tool_exception(reg: ToolRegistry, perms: Permissions) -> None:
    workflow = Workflow(name="demo", steps=(Step(id="boom", uses="kaboom"),))
    results = Executor(registry=reg).run(workflow, inputs={}, permissions=perms)
    assert results["boom"].error is not None
    assert "intentional failure" in results["boom"].error


def test_executor_emits_audit_events_around_steps(
    reg: ToolRegistry, perms: Permissions, tmp_path: Path
) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")
    workflow = Workflow(name="demo", steps=(Step(id="a", uses="echo"),))
    Executor(registry=reg, audit=audit).run(workflow, inputs={}, permissions=perms, run_id="r1")
    events = audit.read()
    assert [e.type for e in events] == ["step_start", "step_end"]
    assert events[0].step_id == "a"
    assert events[1].exit_status == 0


def test_executor_records_unknown_tool_as_step_error(
    perms: Permissions,
) -> None:
    reg = ToolRegistry()
    workflow = Workflow(name="demo", steps=(Step(id="a", uses="ghost.tool"),))
    results = Executor(registry=reg).run(workflow, inputs={}, permissions=perms)
    assert results["a"].error is not None
    assert "ghost.tool" in results["a"].error
