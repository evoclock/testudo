"""
Module: testudo.orchestrator.executor

Purpose: synchronous workflow executor with topological dependency ordering.
Resolves ``${inputs.x}`` and ``${steps.y.z}`` references in step ``with_:``
arguments, evaluates ``when:`` predicates (v0.1 supports ``${ref}`` truthiness
only), invokes the tool registered under ``step.uses``, and emits ``step_start``
and ``step_end`` audit events around each invocation.

Inputs: a ``Workflow``, a dict of inputs, a ``Permissions`` model, and an
optional ``AuditLog``.

Outputs: a dict mapping step IDs to ``StepResult`` (output, skipped flag,
error string).

Assumptions: tool callables follow ``def tool(ctx: StepContext, **kwargs)``.
Async tools and parallel step execution are deferred to v0.2; v0.1 runs steps
in topological order one at a time.

Failure modes: cyclic or unsatisfiable ``needs:`` raise ``RuntimeError`` from
``_topological_sort``; unknown ``${ref}`` references raise ``KeyError`` or
``ValueError`` from ``_resolve``; tool exceptions are caught, logged to the
audit, and recorded on the ``StepResult`` so downstream steps can decide
whether to continue.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from testudo.audit import AuditEvent, AuditLog
from testudo.orchestrator.context import StepContext
from testudo.orchestrator.registry import DEFAULT_REGISTRY, ToolRegistry
from testudo.orchestrator.workflow import Step, Workflow
from testudo.permissions import Permissions


@dataclass(frozen=True, slots=True)
class StepResult:
    """Outcome of one step's execution."""

    id: str
    output: Any = None
    skipped: bool = False
    error: str | None = None


class WorkflowError(RuntimeError):
    """Raised on workflow-level structural failures (cycles, unsatisfiable deps)."""


class Executor:
    """Run a workflow's steps in dependency order."""

    def __init__(
        self,
        registry: ToolRegistry = DEFAULT_REGISTRY,
        audit: AuditLog | None = None,
    ) -> None:
        self.registry = registry
        self.audit = audit

    def run(
        self,
        workflow: Workflow,
        inputs: dict[str, Any],
        permissions: Permissions,
        run_id: str = "local",
    ) -> dict[str, StepResult]:
        """Run all steps in dependency order; return per-step results."""
        ordered = self._topological_sort(workflow.steps)
        step_outputs: dict[str, Any] = {}
        results: dict[str, StepResult] = {}

        for step in ordered:
            ctx = StepContext(
                permissions=permissions,
                audit=self.audit,
                run_id=run_id,
                workflow_name=workflow.name,
                step_id=step.id,
            )

            if step.when is not None:
                try:
                    proceed = self._eval_when(step.when, inputs, step_outputs)
                except (KeyError, ValueError) as exc:
                    self._emit(
                        AuditEvent(
                            type="step_end",
                            run_id=run_id,
                            workflow=workflow.name,
                            step_id=step.id,
                            error=f"when-eval failed: {exc}",
                        )
                    )
                    results[step.id] = StepResult(id=step.id, error=str(exc))
                    continue
                if not proceed:
                    self._emit(
                        AuditEvent(
                            type="step_end",
                            run_id=run_id,
                            workflow=workflow.name,
                            step_id=step.id,
                            decision={"skipped": True, "reason": "when=false"},
                        )
                    )
                    results[step.id] = StepResult(id=step.id, skipped=True)
                    continue

            try:
                args = self._resolve(step.with_, inputs, step_outputs)
            except (KeyError, ValueError) as exc:
                self._emit(
                    AuditEvent(
                        type="step_end",
                        run_id=run_id,
                        workflow=workflow.name,
                        step_id=step.id,
                        error=f"reference resolution failed: {exc}",
                    )
                )
                results[step.id] = StepResult(id=step.id, error=str(exc))
                continue

            try:
                tool = self.registry.resolve(step.uses)
            except KeyError as exc:
                self._emit(
                    AuditEvent(
                        type="step_end",
                        run_id=run_id,
                        workflow=workflow.name,
                        step_id=step.id,
                        error=f"tool resolution failed: {exc}",
                    )
                )
                results[step.id] = StepResult(id=step.id, error=str(exc))
                continue

            self._emit(
                AuditEvent(
                    type="step_start",
                    run_id=run_id,
                    workflow=workflow.name,
                    step_id=step.id,
                    args=args,
                )
            )

            try:
                output = tool(ctx, **args)
            except Exception as exc:
                self._emit(
                    AuditEvent(
                        type="step_end",
                        run_id=run_id,
                        workflow=workflow.name,
                        step_id=step.id,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
                results[step.id] = StepResult(id=step.id, error=f"{type(exc).__name__}: {exc}")
                continue

            self._emit(
                AuditEvent(
                    type="step_end",
                    run_id=run_id,
                    workflow=workflow.name,
                    step_id=step.id,
                    exit_status=0,
                )
            )
            step_outputs[step.id] = output
            results[step.id] = StepResult(id=step.id, output=output)

        return results

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _emit(self, event: AuditEvent) -> None:
        if self.audit is not None:
            self.audit.emit(event)

    @staticmethod
    def _topological_sort(steps: tuple[Step, ...]) -> list[Step]:
        """Order steps so each step's ``needs:`` come first.

        Raises ``WorkflowError`` on cycles or references to unknown step IDs.
        """
        by_id = {s.id: s for s in steps}
        if len(by_id) != len(steps):
            raise WorkflowError("Duplicate step IDs in workflow")

        ordered: list[Step] = []
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node_id: str) -> None:
            if node_id in visited:
                return
            if node_id in visiting:
                raise WorkflowError(f"Cycle detected at step {node_id!r}")
            if node_id not in by_id:
                raise WorkflowError(f"Unknown step ID in needs: {node_id!r}")
            visiting.add(node_id)
            for dep in by_id[node_id].needs:
                visit(dep)
            visiting.discard(node_id)
            visited.add(node_id)
            ordered.append(by_id[node_id])

        for step in steps:
            visit(step.id)
        return ordered

    @classmethod
    def _resolve(
        cls,
        value: Any,
        inputs: dict[str, Any],
        step_outputs: dict[str, Any],
    ) -> Any:
        """Recursively resolve ``${...}`` references inside ``value``.

        Two modes for strings:

        - **Exact match** (``"${some.ref}"``): the entire string is a
          single reference; return the raw resolved value so types are
          preserved (a list stays a list, a dict stays a dict).
        - **Interpolation** (``"prefix ${a.b} suffix"``): each ``${...}``
          inside the string is replaced with ``str(resolved)`` and the
          surrounding text is kept verbatim. The result is always a
          string.
        """
        import re as _re

        if isinstance(value, str):
            stripped = value.strip()
            if (
                stripped.startswith("${")
                and stripped.endswith("}")
                and stripped.count("${") == 1
                and value == stripped
            ):
                return cls._resolve_ref(value[2:-1], inputs, step_outputs)
            if "${" in value:
                pattern = _re.compile(r"\$\{([^${}]+)\}")
                return pattern.sub(
                    lambda m: str(cls._resolve_ref(m.group(1), inputs, step_outputs)),
                    value,
                )
            return value
        if isinstance(value, dict):
            return {k: cls._resolve(v, inputs, step_outputs) for k, v in value.items()}
        if isinstance(value, list):
            return [cls._resolve(v, inputs, step_outputs) for v in value]
        return value

    @staticmethod
    def _resolve_ref(ref: str, inputs: dict[str, Any], step_outputs: dict[str, Any]) -> Any:
        """Resolve a single reference path, e.g. ``"inputs.foo"`` or ``"steps.bar.baz"``."""
        parts = ref.split(".")
        if not parts:
            raise ValueError(f"Empty reference: {ref!r}")

        root = parts[0]
        if root == "inputs":
            value: Any = inputs
        elif root == "steps":
            if len(parts) < 2:
                raise ValueError(f"Reference {ref!r} requires a step ID")
            step_id = parts[1]
            if step_id not in step_outputs:
                raise KeyError(f"Step output not yet available: {step_id!r}")
            value = step_outputs[step_id]
            parts = ["steps", step_id, *parts[2:]]
        else:
            raise ValueError(f"Unknown reference root: {root!r}")

        # walk the remaining attribute path
        offset = 2 if root == "steps" else 1
        for part in parts[offset:]:
            if isinstance(value, dict):
                if part not in value:
                    raise KeyError(f"Missing key {part!r} in reference {ref!r}")
                value = value[part]
            else:
                value = getattr(value, part)
        return value

    @classmethod
    def _eval_when(cls, expr: str, inputs: dict[str, Any], step_outputs: dict[str, Any]) -> bool:
        """v0.1 supports ``${ref}`` truthiness only; no Python expressions."""
        expr = expr.strip()
        if expr.startswith("${") and expr.endswith("}"):
            return bool(cls._resolve_ref(expr[2:-1], inputs, step_outputs))
        raise ValueError(
            f"Invalid when expression: {expr!r} (v0.1 supports ${{ref}} truthiness only)"
        )
