"""
Module: testudo.sanitisers.tools

Purpose: register sanitiser functions as orchestrator tools so workflow steps
can reference them via ``uses: "sanitisers.pii"`` etc. Side effect of importing
this module: every tool below appears in the orchestrator's
``DEFAULT_REGISTRY``.

Inputs: tool kwargs from a workflow's ``with:`` block.

Outputs: a JSON-serialisable dict (the canonical sanitiser-result shape) that
downstream steps consume via ``${steps.<id>.decision}`` etc.

Assumptions: imported by ``testudo.sanitisers.__init__`` so registration
happens automatically when callers ``import testudo.sanitisers``.
"""

from __future__ import annotations

import json
from typing import Any

from testudo.orchestrator.context import StepContext
from testudo.orchestrator.registry import register_tool
from testudo.sanitisers.injection import sanitise_injection
from testudo.sanitisers.pii import sanitise_pii
from testudo.sanitisers.result import Decision, SanitisationResult


def _coerce_to_text(content: Any) -> str:
    """Accept str OR structured data (list/dict) from upstream steps.

    Workflows often pipe ``${steps.query.rows}`` (a list of dicts from a
    SQL adapter) straight into a sanitiser step. Without this coercion
    the regex engine sees a list and throws ``TypeError: expected
    string or bytes-like object``. JSON-encoding preserves all the
    PII / card / secret values verbatim so the regex still matches.
    """
    if isinstance(content, str):
        return content
    if content is None:
        return ""
    return json.dumps(content, indent=2, sort_keys=True, default=str)


def _to_dict(result: SanitisationResult) -> dict[str, Any]:
    """Render a ``SanitisationResult`` as a JSON-serialisable dict."""
    return {
        "decision": result.decision,
        "content": result.content,
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": int(f.severity),
                "category": f.category,
                "label": f.label,
                "evidence": f.evidence,
                "line_number": f.line_number,
            }
            for f in result.findings
        ],
        "critical_count": result.critical_count,
        "high_count": result.high_count,
    }


@register_tool("sanitisers.pii")
def pii_tool(_ctx: StepContext, *, content: Any, redact: bool = False) -> dict[str, Any]:
    """Detect or redact PII in ``content`` (str OR structured data)."""
    return _to_dict(sanitise_pii(_coerce_to_text(content), redact=redact))


@register_tool("sanitisers.injection")
def injection_tool(_ctx: StepContext, *, content: Any) -> dict[str, Any]:
    """Detect prompt-injection patterns in ``content``; reject on any finding."""
    return _to_dict(sanitise_injection(_coerce_to_text(content)))


@register_tool("sanitisers.pii_and_injection")
def combined_tool(_ctx: StepContext, *, content: Any, redact: bool = False) -> dict[str, Any]:
    """Run PII + injection in one pass.

    Accepts ``content`` as ``str`` or any JSON-serialisable structure
    (list / dict). Non-string content is JSON-encoded before regex
    matching so a workflow can pipe e.g. ``${steps.query.rows}`` (a
    list of dicts) straight in.

    With ``redact=True``, PII is replaced with placeholder markers and
    the injection check runs over the cleaned content. Decision is
    "reject" if injection findings exist; otherwise follows the
    PII-pass decision.
    """
    text = _coerce_to_text(content)
    pii_result = sanitise_pii(text, redact=redact)
    inj_result = sanitise_injection(pii_result.content)

    findings = pii_result.findings + inj_result.findings
    decision: Decision
    if not findings:
        decision = "accept"
    elif inj_result.findings:
        decision = "reject"
    else:
        decision = pii_result.decision

    return _to_dict(
        SanitisationResult(decision=decision, content=pii_result.content, findings=findings)
    )
