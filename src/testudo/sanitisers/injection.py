# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.sanitisers.injection

Purpose: prompt-injection pattern detector. Scans content for
ignore-previous-instructions, role-hijack, safety-bypass, hidden HTML
instructions, invisible-instruction, and tool-override patterns. Always rejects
on any finding; injection is too risky to auto-redact.

Inputs: a string of text content to scan.

Outputs: a list of ``Finding`` instances from ``detect_injection``; a
``SanitisationResult`` from ``sanitise_injection`` with decision "reject" on
any finding, "accept" otherwise.

Assumptions: regex-only detection in v0.1. False positives are possible
(especially "invisible-instruction"); callers in lower-risk contexts may
prefer the agent scanner's per-rule thresholds rather than blanket rejection.
"""

from __future__ import annotations

from testudo.sanitisers.patterns import PROMPT_INJECTION_PATTERNS
from testudo.sanitisers.result import Decision, Finding, SanitisationResult, Severity


def detect_injection(content: str) -> list[Finding]:
    """Return prompt-injection findings for ``content``."""
    findings: list[Finding] = []
    for label, pattern in PROMPT_INJECTION_PATTERNS:
        for match in pattern.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            findings.append(
                Finding(
                    rule_id="INJ-001",
                    severity=Severity.HIGH,
                    category="injection",
                    label=label,
                    evidence=match.group().strip()[:200],
                    line_number=line_num,
                )
            )
    return findings


def sanitise_injection(content: str) -> SanitisationResult:
    """Top-level prompt-injection sanitisation.

    Always reject on any finding; do not auto-redact (too easy to misjudge
    intent and silently strip legitimate content).
    """
    findings = detect_injection(content)
    decision: Decision = "reject" if findings else "accept"
    return SanitisationResult(decision=decision, content=content, findings=findings)
