"""Testudo sanitisers package.

Purpose: input safety checks. v0.1 ships PII detection (regex plus a lightweight
NER pass) and prompt-injection-pattern detection. v0.2 will add file-format exploit
detection.

Inputs: a ``StagedInput`` from ``connectors/``.

Outputs: a ``SanitisationResult`` carrying the cleaned content, a list of findings
(category, span, severity), and a decision (accept, redact, reject) the orchestrator
uses to gate the workflow step.

Assumptions: sanitisation runs inside the container so failures cannot bypass it;
findings are written to the audit log even when the result is "accept" so the
review trail is complete.
"""
