"""
Module: testudo.permissions.scan

Purpose: scan-before-permit gate. Per MCP presentation v4 slide 24 ("policy
sits between model and action") and the user direction 2026-05-12 ("use our
own agent-scan implementation from hillstar within testudo to scan before
giving perms"). The :class:`AgentScanner` from
:mod:`testudo.sanitisers.agent_scanner` runs against the artifact first; if
any CRITICAL (or HIGH, by default) finding fires the scan raises
:class:`ScanRejected` before the permission check has a chance to grant
access.

Inputs: a path or scanner-output, plus the relevant permissions sub-model.

Outputs: ``None`` from the ``require_*_scanned`` helpers; a
:class:`ScanRejected` raised when the scan finds an unacceptable issue, or
:class:`PermissionDenied` raised when the post-scan permission check fails.

Assumptions: scanning is meaningful only for recognised supply-chain
artifacts (MCP configs, skill files, ``.claude.json``-style files). The
``should_scan`` heuristic decides; non-matching paths fall through to the
plain permission check unchanged.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from testudo.permissions.enforce import (
    PermissionDenied,
    require_filesystem_read,
    require_filesystem_write,
)
from testudo.permissions.model import FilesystemPermissions

if TYPE_CHECKING:
    from testudo.sanitisers.agent_scanner import AgentScanner, ScanResult

# Severity is duplicated here as a tiny IntEnum so this module stays free of
# any sanitisers import at module-load time. The real Severity lives in
# testudo.sanitisers.result; values match.
from enum import IntEnum


class Severity(IntEnum):
    """Mirrors :class:`testudo.sanitisers.result.Severity` for the gate.

    Re-defined locally to keep this module import-free of the sanitisers
    package. The enum values are the same; the gate only ever compares
    integers, never the enum identity.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


SCAN_SUFFIXES: frozenset[str] = frozenset({".json", ".md"})
SCAN_NAME_HINTS: frozenset[str] = frozenset(
    {
        "mcp.json",
        ".mcp.json",
        ".claude.json",
        "claude_desktop_config.json",
        "skill.md",
        "skills.md",
    }
)
SCAN_DIR_HINTS: frozenset[str] = frozenset({".claude", ".cursor", ".windsurf", "skills"})


class ScanRejected(Exception):
    """Raised when a scan-before-permit gate refuses an artifact."""

    def __init__(self, *, path: str, reason: str, result: ScanResult) -> None:
        super().__init__(f"ScanRejected: {path!r} ({reason})")
        self.path = path
        self.reason = reason
        self.result = result


def should_scan(path: str | Path) -> bool:
    """Return True iff the path looks like an MCP config or skill artifact."""
    p = Path(path)
    if p.name in SCAN_NAME_HINTS:
        return True
    if p.suffix.lower() not in SCAN_SUFFIXES:
        return False
    if any(part in SCAN_DIR_HINTS for part in p.parts):
        return True
    return "skill" in p.name.lower()


def scan_artifact(
    path: str | Path,
    *,
    scanner: type[AgentScanner] | None = None,
) -> ScanResult:
    """Run the agent scanner against ``path`` and return the raw result."""
    if scanner is None:
        from testudo.sanitisers.agent_scanner import AgentScanner as _AgentScanner

        scanner = _AgentScanner
    return scanner.scan_path(Path(path))


def evaluate_scan(
    result: ScanResult,
    *,
    block_severity: Severity = Severity.HIGH,
) -> tuple[bool, str]:
    """Return ``(ok, reason)`` from a scan result.

    ``ok=False`` if any finding meets or exceeds ``block_severity``. Reason
    summarises the worst finding so the audit-log entry is readable.
    """
    worst = max((f.severity for f in result.findings), default=Severity.INFO)
    if worst < block_severity:
        return True, ""
    worst_findings = [f for f in result.findings if f.severity == worst]
    labels = sorted({f.label for f in worst_findings})
    return False, f"{worst.name} findings: {', '.join(labels[:5])}"


def require_filesystem_read_scanned(
    path: str | Path,
    perms: FilesystemPermissions,
    *,
    block_severity: Severity = Severity.HIGH,
    scanner: type[AgentScanner] | None = None,
) -> None:
    """Scan-then-permit gate for filesystem reads.

    For paths matching :func:`should_scan` the scanner runs first; a
    finding at or above ``block_severity`` raises :class:`ScanRejected`
    before the permission check is consulted. Otherwise the plain
    :func:`require_filesystem_read` runs.
    """
    if should_scan(path):
        result = scan_artifact(path, scanner=scanner)
        ok, reason = evaluate_scan(result, block_severity=block_severity)
        if not ok:
            raise ScanRejected(path=str(path), reason=reason, result=result)
    require_filesystem_read(path, perms)


def require_filesystem_write_scanned(
    path: str | Path,
    perms: FilesystemPermissions,
    *,
    block_severity: Severity = Severity.HIGH,
    scanner: type[AgentScanner] | None = None,
) -> None:
    """Scan-then-permit gate for filesystem writes.

    The scan applies when the *target* path is an MCP-config or skill-like
    artifact. The intent is to refuse writes that would land an attacker
    payload into a supply-chain location (e.g. overwriting ``.mcp.json``).
    """
    if should_scan(path) and Path(path).exists():
        result = scan_artifact(path, scanner=scanner)
        ok, reason = evaluate_scan(result, block_severity=block_severity)
        if not ok:
            raise ScanRejected(path=str(path), reason=reason, result=result)
    require_filesystem_write(path, perms)


__all__ = [
    "SCAN_DIR_HINTS",
    "SCAN_NAME_HINTS",
    "SCAN_SUFFIXES",
    "PermissionDenied",
    "ScanRejected",
    "Severity",
    "evaluate_scan",
    "require_filesystem_read_scanned",
    "require_filesystem_write_scanned",
    "scan_artifact",
    "should_scan",
]
