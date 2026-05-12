"""
Module: testudo.sanitisers.pii

Purpose: regex-based UK-flavoured PII detection and optional redaction.
``detect_pii`` returns findings without modifying content; ``redact_pii``
returns the cleaned content (with matches replaced by placeholder tokens) plus
findings; ``sanitise_pii`` produces a top-level ``SanitisationResult`` with a
decision (accept / redact / reject).

Inputs: a string of text content to scan.

Outputs: a list of ``Finding`` instances; ``(content, findings)`` from
``redact_pii``; a ``SanitisationResult`` from ``sanitise_pii``.

Assumptions: regex-only in v0.1; the ``[sanitisers]`` extra (spaCy, Presidio)
will land in v0.2 for higher-recall detection of names, addresses, and
context-dependent identifiers. Callers needing higher recall should use the
extras and a dedicated NER-based detector.
"""

from __future__ import annotations

from testudo.sanitisers.patterns import UK_PII_PATTERNS
from testudo.sanitisers.result import Finding, SanitisationResult, Severity


def detect_pii(content: str) -> list[Finding]:
    """Return PII findings for ``content`` without modifying it."""
    findings: list[Finding] = []
    for label, pattern in UK_PII_PATTERNS:
        for match in pattern.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            findings.append(
                Finding(
                    rule_id="PII-001",
                    severity=Severity.HIGH,
                    category="pii",
                    label=label,
                    evidence=match.group()[:50],
                    line_number=line_num,
                )
            )
    return findings


def redact_pii(content: str) -> tuple[str, list[Finding]]:
    """Detect PII and replace matches with ``[REDACTED-<short label>]`` markers."""
    findings = detect_pii(content)
    cleaned = content
    for label, pattern in UK_PII_PATTERNS:
        marker = f"[REDACTED-{_short_label(label)}]"
        cleaned = pattern.sub(marker, cleaned)
    return cleaned, findings


def sanitise_pii(content: str, *, redact: bool = False) -> SanitisationResult:
    """Top-level PII sanitisation.

    With ``redact=False`` (default), any PII finding triggers a "reject"
    decision and the original content is returned untouched. With
    ``redact=True``, PII is replaced with placeholder markers and the decision
    is "redact" if findings were present, "accept" otherwise.
    """
    if redact:
        cleaned, findings = redact_pii(content)
        decision = "redact" if findings else "accept"
        return SanitisationResult(decision=decision, content=cleaned, findings=findings)

    findings = detect_pii(content)
    decision = "reject" if findings else "accept"
    return SanitisationResult(decision=decision, content=content, findings=findings)


def _short_label(label: str) -> str:
    """Produce a short uppercase tag for the redaction marker."""
    return label.replace("UK ", "").replace(" ", "-").upper()
