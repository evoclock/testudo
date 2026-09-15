# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.sanitisers.threat

Purpose: detect OWASP Top 10 (web) injection families plus OWASP MCP Top 10
threat markers. Covers SQL/NoSQL injection, command injection, path
traversal, XXE, SSRF, template injection, XSS, LDAP/XPath injection on the
OWASP-web side; and tool poisoning, rug-pull markers, indirect prompt
injection (slide 17 of the MCP presentation), confused deputy, and
AI recommendation poisoning on the MCP side.

Inputs: a string of text content (request body, model output, document
chunk, MCP tool description, etc.).

Outputs: ``detect_threats`` returns a list of ``Finding``; ``sanitise_threat``
wraps it in a ``SanitisationResult`` with a "reject" decision on any
finding (these classes are too risky to auto-redact).

Assumptions: regex detection only. False positives are expected for the
generic SQL boolean tautology and the broad OWASP markers; treat the
output as an investigation prompt, not an automated block in production.
"""

from __future__ import annotations

from testudo.sanitisers.patterns import (
    MCP_THREAT_PATTERNS,
    OWASP_INJECTION_PATTERNS,
)
from testudo.sanitisers.result import Decision, Finding, SanitisationResult, Severity


def detect_owasp(content: str) -> list[Finding]:
    """Return OWASP-web injection findings for ``content``."""
    findings: list[Finding] = []
    for label, pattern in OWASP_INJECTION_PATTERNS:
        for match in pattern.finditer(content):
            findings.append(
                Finding(
                    rule_id="OWASP-001",
                    severity=_owasp_severity(label),
                    category="owasp-injection",
                    label=label,
                    evidence=match.group()[:200],
                    line_number=content[: match.start()].count("\n") + 1,
                )
            )
    return findings


def detect_mcp_threats(content: str) -> list[Finding]:
    """Return OWASP MCP Top 10 + recommendation-poisoning findings."""
    findings: list[Finding] = []
    for label, pattern in MCP_THREAT_PATTERNS:
        for match in pattern.finditer(content):
            findings.append(
                Finding(
                    rule_id="MCP-THREAT-001",
                    severity=Severity.HIGH,
                    category="mcp-threat",
                    label=label,
                    evidence=match.group()[:200],
                    line_number=content[: match.start()].count("\n") + 1,
                )
            )
    return findings


def detect_threats(content: str) -> list[Finding]:
    """Run both OWASP-web and MCP detectors and return the combined findings."""
    return detect_owasp(content) + detect_mcp_threats(content)


def sanitise_threat(content: str) -> SanitisationResult:
    """Top-level threat sanitisation: reject on any finding."""
    findings = detect_threats(content)
    decision: Decision = "reject" if findings else "accept"
    return SanitisationResult(decision=decision, content=content, findings=findings)


def _owasp_severity(label: str) -> Severity:
    """Return a severity that reflects the threat class.

    SQL injection, command injection, XXE and SSRF are CRITICAL; XSS,
    template injection, LDAP/XPath are HIGH; the rest fall back to MEDIUM.
    """
    lower = label.lower()
    if any(k in lower for k in ("sql:", "command:", "xxe:", "ssrf:")):
        return Severity.CRITICAL
    if any(k in lower for k in ("xss:", "template injection", "ldap injection", "xpath")):
        return Severity.HIGH
    return Severity.MEDIUM
