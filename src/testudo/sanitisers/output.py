# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.sanitisers.output

Purpose: output-side sanitisation pipeline. Anything an LLM emits (chat
text, tool-call arguments, file content destined for disk) passes through
this pipeline before reaching the write-side MCP server. Composes
hidden-unicode stripping, secret redaction, PII redaction, prompt-injection
rejection, and OWASP/MCP threat rejection in that order.

Inputs: a string of model output.

Outputs: ``sanitise_output`` returns a ``SanitisationResult`` whose decision
is:

- ``reject`` if any prompt-injection or OWASP/MCP-threat finding fires
  (these classes cannot be auto-redacted).
- ``redact`` if hidden-unicode, secret, or PII findings fire and content
  was modified.
- ``accept`` otherwise.

The cleaned content is always the post-pipeline string; even on reject we
return the partially-cleaned content so the caller can show the operator
exactly what would have been sent.

Assumptions: the pipeline runs in a fixed order. Hidden payloads first
(they can hide everything downstream); then secret redaction; then PII
redaction; then injection and OWASP/MCP threat detection. Re-ordering
breaks the "strip before detect" invariant.

References:

- User direction 2026-05-12: LLM responses return via a read-only MCP
  server, are sanitised, and only then handed to the read/write MCP
  server (modelled on hillstar's ``file_operations_mcp_server.py``).
- MCP presentation v4 slides 24-25: policy as the safety boundary;
  everything an LLM reads is executable; separate extraction from action.
"""

from __future__ import annotations

import re

from testudo.sanitisers.injection import detect_injection
from testudo.sanitisers.patterns import SECRET_PATTERNS
from testudo.sanitisers.pii import redact_pii
from testudo.sanitisers.result import Decision, Finding, SanitisationResult, Severity
from testudo.sanitisers.threat import detect_threats
from testudo.sanitisers.unicode_payload import strip_hidden


def redact_secrets(content: str) -> tuple[str, list[Finding]]:
    """Detect and redact secrets in ``content``.

    Each matched secret is replaced with ``[REDACTED-<label>]``. Returns
    the cleaned content plus the list of findings for the matches that
    were present in the original input.
    """
    findings: list[Finding] = []
    for label, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(content):
            findings.append(
                Finding(
                    rule_id="SECRET-001",
                    severity=Severity.CRITICAL,
                    category="secret",
                    label=label,
                    evidence="<redacted>",
                    line_number=content[: match.start()].count("\n") + 1,
                )
            )

    cleaned = content
    for label, pattern in SECRET_PATTERNS:
        marker = f"[REDACTED-{_short_label(label)}]"
        cleaned = pattern.sub(marker, cleaned)
    return cleaned, findings


def sanitise_output(content: str) -> SanitisationResult:
    """Run the output sanitiser pipeline.

    Order:

    1. Strip hidden-unicode and comment payloads.
    2. Redact secrets.
    3. Redact PII (UK + international + country).
    4. Detect prompt injection.
    5. Detect OWASP-web and MCP-specific threats.

    Decision is rejection-priority: any injection or threat finding
    short-circuits to ``reject``. Otherwise ``redact`` if any earlier
    stage produced a finding; ``accept`` if nothing fired.
    """
    cleaned, hidden_findings = strip_hidden(content)
    cleaned, secret_findings = redact_secrets(cleaned)
    cleaned, pii_findings = redact_pii(cleaned)

    injection_findings = detect_injection(cleaned)
    threat_findings = detect_threats(cleaned)

    all_findings: list[Finding] = (
        hidden_findings + secret_findings + pii_findings + injection_findings + threat_findings
    )

    decision: Decision
    if injection_findings or threat_findings:
        decision = "reject"
    elif hidden_findings or secret_findings or pii_findings:
        decision = "redact"
    else:
        decision = "accept"

    return SanitisationResult(decision=decision, content=cleaned, findings=all_findings)


def sanitise_input(content: str) -> SanitisationResult:
    """Run the input sanitiser pipeline.

    Same stages as :func:`sanitise_output`, but used on data coming *into*
    a workflow (file uploads, fetched URLs, MCP tool results). The
    decision logic is identical; the two functions are kept distinct so
    callers can attach an audit-event type that captures direction.
    """
    return sanitise_output(content)


_NON_ALNUM = re.compile(r"[^A-Za-z0-9]+")


def _short_label(label: str) -> str:
    """Produce a redaction-marker-safe short tag from a finding label."""
    return _NON_ALNUM.sub("-", label).strip("-").upper()
