# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Testudo sanitisers package.

Purpose: input safety checks for workflow content. v0.1 ships UK-flavoured
PII detection (regex-based, with optional redaction), prompt-injection
pattern detection (always strict), and the agent scanner ported from
hillstar (a static security scanner for MCP configs and skill files).

Inputs: text content from a workflow step (PII / injection sanitisers) or
a file/directory path (agent scanner).

Outputs: a ``SanitisationResult`` with decision (accept / redact / reject)
plus a list of ``Finding``; or a ``ScanResult`` from the agent scanner.

Assumptions: regex-only detection in v0.1. The ``[sanitisers]`` extra (spaCy,
Presidio) lands in v0.2 for higher-recall detection of names, addresses, and
context-dependent identifiers.

Side effect: importing this package triggers registration of the ``sanitisers.pii``,
``sanitisers.injection``, and ``sanitisers.pii_and_injection`` tools in the
orchestrator's ``DEFAULT_REGISTRY``.
"""

from testudo.sanitisers import tools  # noqa: F401  - registers sanitiser tools
from testudo.sanitisers.agent_scanner import AgentScanner, ScanResult
from testudo.sanitisers.injection import detect_injection, sanitise_injection
from testudo.sanitisers.output import sanitise_input, sanitise_output
from testudo.sanitisers.pii import detect_pii, redact_pii, sanitise_pii
from testudo.sanitisers.result import (
    Decision,
    Finding,
    SanitisationResult,
    Severity,
)
from testudo.sanitisers.threat import (
    detect_mcp_threats,
    detect_owasp,
    detect_threats,
    sanitise_threat,
)
from testudo.sanitisers.unicode_payload import (
    detect_hidden,
    sanitise_hidden,
    strip_hidden,
)

__all__ = [
    "AgentScanner",
    "Decision",
    "Finding",
    "SanitisationResult",
    "ScanResult",
    "Severity",
    "detect_hidden",
    "detect_injection",
    "detect_mcp_threats",
    "detect_owasp",
    "detect_pii",
    "detect_threats",
    "redact_pii",
    "sanitise_hidden",
    "sanitise_injection",
    "sanitise_input",
    "sanitise_output",
    "sanitise_pii",
    "sanitise_threat",
    "strip_hidden",
]
