"""
Module: testudo.sanitisers.pii

Purpose: regex-based PII detection and optional redaction. Covers the
UK-flavoured set (NIN, email, phone, NHS number, postcode) plus an
international set (US SSN, credit cards, IBAN, IPv4, IPv6, E.164,
generic dd/mm/yyyy date-of-birth). ``detect_pii`` returns findings
without modifying content; ``redact_pii`` returns the cleaned content
with matches replaced by placeholder tokens; ``sanitise_pii`` produces
a top-level ``SanitisationResult`` with an accept / redact / reject
decision.

Inputs: a string of text content to scan.

Outputs: a list of ``Finding`` instances; ``(content, findings)`` from
``redact_pii``; a ``SanitisationResult`` from ``sanitise_pii``.

Limitations (v0.1 — regex only):

- Unstructured text breaks rule-based regex: phrasings like "five five
  five one two 88" or "born 3rd of Feb '88" lack the canonical formats
  the patterns expect.
- Context is invisible to regex: relational PII (e.g. "my daughter
  Emily attends Ridgewood Elementary") is sensitive only when entity
  relationships are understood. v0.1 does not detect this class.
- False-positive rate scales with prose: the date-of-birth and IPv4
  patterns in particular flag any matching string regardless of
  surrounding context.
- Country coverage is breadth-first via ``COUNTRY_PII_PATTERNS``: ~50
  countries (Canada SIN, Brazil CPF/CNPJ, India Aadhaar/PAN, Singapore
  NRIC/FIN, Australia TFN/Medicare/ABN, Spain DNI/NIE, France INSEE,
  Germany Steuer-ID, etc.). Several patterns match plain digit runs
  (Netherlands BSN ``\\d{9}``, Bangladesh NID ``\\d{10,17}``); the
  v0.2 NER hybrid is what disambiguates these.

The v0.2 plan (under the ``[sanitisers]`` extra) adds spaCy NER for
named entities, Microsoft Presidio for context-aware detection, and a
confidence-ranked merge of regex + NER + metadata signals. The
documented hybrid approach follows Protecto's "Why Regex Fails for
PII Detection in Unstructured Text" pipeline (regex for strict
patterns, NER for contextual entities, confidence ranking for
prioritisation).

Assumptions: callers needing higher recall (legal e-discovery,
healthcare PHI, financial PCI workflows) install the ``[sanitisers]``
extra in v0.2 and use the hybrid pipeline rather than this regex-only
detector.
"""

from __future__ import annotations

from testudo.sanitisers.patterns import ALL_PII_PATTERNS
from testudo.sanitisers.result import Finding, SanitisationResult, Severity


def detect_pii(content: str) -> list[Finding]:
    """Return PII findings for ``content`` without modifying it."""
    findings: list[Finding] = []
    for label, pattern in ALL_PII_PATTERNS:
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
    """Detect PII and replace matches with ``[REDACTED-<short label>]`` markers.

    Single-pass: every pattern matches against the *original* content; the
    earliest non-overlapping match wins. This prevents one substitution's
    output (e.g. ``[REDACTED-EMAIL-ADDRESS]``) from accidentally matching a
    later, broader pattern (e.g. BIC/SWIFT against the ``REDACTED`` token).
    """
    findings = detect_pii(content)

    matches: list[tuple[int, int, str]] = []
    for label, pattern in ALL_PII_PATTERNS:
        for m in pattern.finditer(content):
            matches.append((m.start(), m.end(), label))

    matches.sort(key=lambda x: (x[0], -(x[1] - x[0])))

    selected: list[tuple[int, int, str]] = []
    last_end = -1
    for start, end, label in matches:
        if start >= last_end:
            selected.append((start, end, label))
            last_end = end

    parts: list[str] = []
    cursor = 0
    for start, end, label in selected:
        parts.append(content[cursor:start])
        parts.append(f"[REDACTED-{_short_label(label)}]")
        cursor = end
    parts.append(content[cursor:])
    return "".join(parts), findings


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
