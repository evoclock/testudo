"""
Module: testudo.sanitisers.unicode_payload

Purpose: detect and strip hidden-unicode and comment payloads. Per MCP
presentation v4 slide 25, zero-width characters, bidi overrides, HTML
comments, and inline base64 are invisible to humans but visible to language
models. Anything an LLM might read (attachments, linked content, imported
skills) is sanitised on input via this module.

Inputs: a string of text content.

Outputs: ``detect_hidden`` returns a list of ``Finding``; ``strip_hidden``
returns ``(cleaned, findings)`` with hidden characters and comment payloads
removed; ``sanitise_hidden`` returns a ``SanitisationResult`` with the
cleaned content and a "redact" decision when anything was stripped.

Assumptions: stripping is destructive of the matched span (zero-width
characters and HTML comments are removed entirely; base64 blobs are
replaced with a placeholder marker so reviewers see the size of the
removed chunk).

References:

- MCP presentation v4 slide 25 (extraction-vs-action separation).
- CVE-2026-21852 (ANTHROPIC_BASE_URL exfiltration).
- ASCII smuggling literature (Riley Goodside, 2024).
"""

from __future__ import annotations

from testudo.sanitisers.patterns import (
    COMMENT_PAYLOAD_PATTERNS,
    HIDDEN_UNICODE_PATTERNS,
    INVISIBLE_CHARS,
)
from testudo.sanitisers.result import Decision, Finding, SanitisationResult, Severity


def detect_hidden(content: str) -> list[Finding]:
    """Return findings for hidden-unicode and comment-payload matches."""
    findings: list[Finding] = []
    for label, pattern in HIDDEN_UNICODE_PATTERNS:
        for match in pattern.finditer(content):
            findings.append(
                Finding(
                    rule_id="HIDDEN-001",
                    severity=Severity.HIGH,
                    category="hidden-unicode",
                    label=label,
                    evidence=f"U+{ord(match.group()):04X}",
                    line_number=content[: match.start()].count("\n") + 1,
                    description=(
                        "Invisible character can carry instructions or steganographic "
                        "payload that humans miss but LLMs ingest."
                    ),
                )
            )

    for label, pattern in COMMENT_PAYLOAD_PATTERNS:
        for match in pattern.finditer(content):
            evidence = match.group()[:120]
            findings.append(
                Finding(
                    rule_id="HIDDEN-002",
                    severity=Severity.HIGH,
                    category="comment-payload",
                    label=label,
                    evidence=evidence,
                    line_number=content[: match.start()].count("\n") + 1,
                    description=(
                        "HTML comments, base64 blobs, and base-URL overrides are common "
                        "carriers for hidden instructions and credential exfiltration."
                    ),
                )
            )

    return findings


def strip_hidden(content: str) -> tuple[str, list[Finding]]:
    """Strip hidden characters, comment payloads, and base64 blobs from ``content``.

    HTML comments and zero-width / bidi-control characters are removed entirely.
    Inline base64 data URIs and buried base64 blobs are replaced with
    ``[REDACTED-BASE64-<n>B]`` markers so reviewers can see the size of the
    removed chunk. ANTHROPIC_BASE_URL and other API base-URL overrides are
    replaced with ``[REDACTED-BASE-URL-OVERRIDE]``.
    """
    findings = detect_hidden(content)
    cleaned = content

    cleaned = "".join(ch for ch in cleaned if ch not in INVISIBLE_CHARS)

    for label, pattern in COMMENT_PAYLOAD_PATTERNS:
        if "base64" in label.lower():
            cleaned = pattern.sub(
                lambda m: f"[REDACTED-BASE64-{len(m.group())}B]",
                cleaned,
            )
        elif "BASE_URL" in label or "base url" in label.lower():
            cleaned = pattern.sub("[REDACTED-BASE-URL-OVERRIDE]", cleaned)
        else:
            cleaned = pattern.sub("", cleaned)

    return cleaned, findings


def sanitise_hidden(content: str) -> SanitisationResult:
    """Top-level hidden-payload sanitisation. Strips on any finding.

    Decision is "redact" if any hidden payload was found and stripped,
    "accept" otherwise.
    """
    cleaned, findings = strip_hidden(content)
    decision: Decision = "redact" if findings else "accept"
    return SanitisationResult(decision=decision, content=cleaned, findings=findings)
