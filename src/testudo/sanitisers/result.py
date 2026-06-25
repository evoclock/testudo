# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.sanitisers.result

Purpose: dataclass models for sanitiser output. ``Finding`` is the common
envelope used by every sanitiser (PII detector, prompt-injection detector,
agent scanner) to report one matched issue. ``SanitisationResult`` aggregates
a decision (accept / redact / reject), the (possibly redacted) content, and
the list of findings.

Inputs: constructor arguments built by the sanitiser modules.

Outputs: frozen ``Finding`` instances; mutable ``SanitisationResult`` (callers
may append findings while building up a multi-pass result).

Assumptions: the JSON-shape of ``SanitisationResult`` is part of the workflow
public API; downstream steps consume it via ``${steps.x.findings}`` etc.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Literal

Decision = Literal["accept", "redact", "reject"]


class Severity(IntEnum):
    """Finding severity levels. Higher integer means worse."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True, slots=True)
class Finding:
    """One matched sanitiser issue.

    ``file_path`` and ``server_name`` are populated only by the agent scanner
    (which works on MCP configs and skill files); content sanitisers leave
    them as ``None``.
    """

    rule_id: str
    severity: Severity
    category: str
    label: str
    evidence: str = ""
    line_number: int = 0
    description: str | None = None
    file_path: str | None = None
    server_name: str | None = None


@dataclass(slots=True)
class SanitisationResult:
    """Aggregated sanitiser output."""

    decision: Decision
    content: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)
