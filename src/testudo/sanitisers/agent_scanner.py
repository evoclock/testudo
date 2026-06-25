# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.sanitisers.agent_scanner

Purpose: static security scanner for MCP server configurations and agent skill
files. Ported from ``~/hillstar-orchestrator/workflows/agent_scanner.py`` and
adapted to use Testudo's ``Finding``/``SanitisationResult`` types. Detects
hardcoded secrets, shell injection, prompt injection, data exfiltration,
untrusted endpoints, and dangerous command flags without starting any servers.

Inputs: paths to MCP config files (JSON), agent skill files (Markdown), or
directories containing them.

Outputs: a ``ScanResult`` with a list of ``Finding`` instances plus
``files_scanned`` and ``servers_scanned`` counts.

Assumptions: MCP configs follow the Claude Code / Cursor / Windsurf JSON
format. Skill files are Markdown with optional code blocks. Scanning is
read-only and never executes any server, command, or skill.

Failure modes: unreadable files emit an INFO finding and continue; invalid
JSON emits an INFO finding and skips structured analysis (raw secret check
still runs); empty directories return an empty ``ScanResult``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from testudo.sanitisers.patterns import (
    DANGEROUS_FLAGS,
    DESTRUCTIVE_PATTERNS,
    EXFILTRATION_PATTERNS,
    PROMPT_INJECTION_PATTERNS,
    SECRET_ENV_NAMES,
    SECRET_PATTERNS,
    SHELL_INJECTION_PATTERNS,
)
from testudo.sanitisers.result import Finding, Severity


@dataclass(slots=True)
class ScanResult:
    """Aggregated scan results across multiple files and servers."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    servers_scanned: int = 0

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


class AgentScanner:
    """Static security scanner for MCP configs and agent skill files."""

    @classmethod
    def scan_mcp_config(cls, file_path: Path) -> ScanResult:
        """Scan an MCP configuration file for security issues."""
        result = ScanResult()
        path_str = str(file_path)

        try:
            raw = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            result.findings.append(
                Finding(
                    rule_id="SCAN-001",
                    severity=Severity.INFO,
                    category="scanner",
                    label="File unreadable",
                    description=str(exc),
                    file_path=path_str,
                )
            )
            return result

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            result.findings.append(
                Finding(
                    rule_id="SCAN-002",
                    severity=Severity.INFO,
                    category="scanner",
                    label="Invalid JSON",
                    description=str(exc),
                    file_path=path_str,
                )
            )
            return result

        result.files_scanned = 1

        for name, server_cfg in cls._extract_servers(data).items():
            result.servers_scanned += 1
            cls._check_server(name, server_cfg, path_str, result)

        cls._check_raw_secrets(raw, path_str, result)
        return result

    @classmethod
    def scan_skill_file(cls, file_path: Path) -> ScanResult:
        """Scan a skill or prompt Markdown file for security issues."""
        import re

        result = ScanResult()
        path_str = str(file_path)

        try:
            content = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            result.findings.append(
                Finding(
                    rule_id="SCAN-001",
                    severity=Severity.INFO,
                    category="scanner",
                    label="File unreadable",
                    description=str(exc),
                    file_path=path_str,
                )
            )
            return result

        result.files_scanned = 1

        for label, pattern in PROMPT_INJECTION_PATTERNS:
            for match in pattern.finditer(content):
                result.findings.append(
                    Finding(
                        rule_id="SKILL-001",
                        severity=Severity.HIGH,
                        category="injection",
                        label=f"Prompt injection: {label}",
                        evidence=match.group().strip()[:200],
                        line_number=content[: match.start()].count("\n") + 1,
                        description=(
                            f"Skill contains prompt injection pattern: {label}. "
                            "Could override safety guardrails or hijack agent behavior."
                        ),
                        file_path=path_str,
                    )
                )

        for label, pattern in EXFILTRATION_PATTERNS:
            for match in pattern.finditer(content):
                result.findings.append(
                    Finding(
                        rule_id="SKILL-002",
                        severity=Severity.CRITICAL,
                        category="exfiltration",
                        label=f"Data exfiltration: {label}",
                        evidence=match.group().strip()[:200],
                        line_number=content[: match.start()].count("\n") + 1,
                        description=(
                            f"Skill references sensitive data or remote endpoint: {label}."
                        ),
                        file_path=path_str,
                    )
                )

        for label, pattern in DESTRUCTIVE_PATTERNS:
            for match in pattern.finditer(content):
                result.findings.append(
                    Finding(
                        rule_id="SKILL-003",
                        severity=Severity.CRITICAL,
                        category="destructive",
                        label=f"Destructive command: {label}",
                        evidence=match.group().strip()[:200],
                        line_number=content[: match.start()].count("\n") + 1,
                        description=(f"Skill contains destructive command pattern: {label}."),
                        file_path=path_str,
                    )
                )

        # Shell injection inside fenced code blocks only
        for block in re.findall(
            r"```(?:bash|sh|shell)?\n(.*?)```",
            content,
            re.DOTALL,
        ):
            for label, pattern in SHELL_INJECTION_PATTERNS:
                for match in pattern.finditer(block):
                    block_start = content.find(block)
                    line_num = content[: block_start + match.start()].count("\n") + 1
                    result.findings.append(
                        Finding(
                            rule_id="SKILL-004",
                            severity=Severity.HIGH,
                            category="shell-injection",
                            label=f"Shell injection in code block: {label}",
                            evidence=match.group().strip()[:200],
                            line_number=line_num,
                            description=(
                                f"Code block contains potentially dangerous pattern: {label}."
                            ),
                            file_path=path_str,
                        )
                    )

        return result

    @classmethod
    def scan_path(cls, target: Path) -> ScanResult:
        """Scan a file or directory, auto-detecting file types."""
        if target.is_file():
            if target.suffix == ".json":
                return cls.scan_mcp_config(target)
            if target.suffix == ".md":
                return cls.scan_skill_file(target)
            return ScanResult(
                findings=[
                    Finding(
                        rule_id="SCAN-003",
                        severity=Severity.INFO,
                        category="scanner",
                        label="Unsupported file type",
                        description=f"Cannot scan {target.suffix} files",
                        file_path=str(target),
                    )
                ]
            )

        result = ScanResult()
        if target.is_dir():
            for pattern in ("**/mcp.json", "**/.mcp.json", "**/.claude.json"):
                for path in sorted(target.glob(pattern)):
                    sub = cls.scan_mcp_config(path)
                    result.findings.extend(sub.findings)
                    result.files_scanned += sub.files_scanned
                    result.servers_scanned += sub.servers_scanned

            for path in sorted(target.glob("**/*.md")):
                if "skill" in path.name.lower() or "skills" in str(path).lower():
                    sub = cls.scan_skill_file(path)
                    result.findings.extend(sub.findings)
                    result.files_scanned += sub.files_scanned

        return result

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_servers(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """Extract MCP server definitions from various config formats."""
        servers: dict[str, dict[str, Any]] = {}

        if "mcpServers" in data and isinstance(data["mcpServers"], dict):
            servers.update(data["mcpServers"])

        if "projects" in data and isinstance(data["projects"], dict):
            for proj_cfg in data["projects"].values():
                if isinstance(proj_cfg, dict) and isinstance(proj_cfg.get("mcpServers"), dict):
                    servers.update(proj_cfg["mcpServers"])

        return servers

    @staticmethod
    def _check_server(
        name: str,
        cfg: dict[str, Any],
        file_path: str,
        result: ScanResult,
    ) -> None:
        env = cfg.get("env", {})
        if isinstance(env, dict):
            for env_key, env_val in env.items():
                if env_key.upper() in SECRET_ENV_NAMES:
                    val_str = str(env_val)
                    if not (val_str.startswith("${") or val_str.startswith("$")):
                        result.findings.append(
                            Finding(
                                rule_id="MCP-001",
                                severity=Severity.CRITICAL,
                                category="secret",
                                label=f"Hardcoded secret in env: {env_key}",
                                evidence=(
                                    f"{env_key}={val_str[:8]}{'*' * max(0, len(val_str) - 8)}"
                                ),
                                file_path=file_path,
                                server_name=name,
                                description=(
                                    f"Server '{name}' has sensitive env var "
                                    f"'{env_key}' with a hardcoded value."
                                ),
                            )
                        )

                for label, pattern in SECRET_PATTERNS:
                    if pattern.search(str(env_val)):
                        result.findings.append(
                            Finding(
                                rule_id="MCP-002",
                                severity=Severity.CRITICAL,
                                category="secret",
                                label=f"Secret pattern in env value: {label}",
                                evidence=f"{env_key}=<redacted>",
                                file_path=file_path,
                                server_name=name,
                                description=(
                                    f"Server '{name}' env var '{env_key}' "
                                    f"matches the pattern for {label}."
                                ),
                            )
                        )

        command = cfg.get("command", "")
        args = cfg.get("args", [])
        full_cmd = f"{command} {' '.join(str(a) for a in args)}" if args else command

        if full_cmd:
            for label, pattern in SHELL_INJECTION_PATTERNS:
                if pattern.search(full_cmd):
                    result.findings.append(
                        Finding(
                            rule_id="MCP-003",
                            severity=Severity.HIGH,
                            category="shell-injection",
                            label=f"Shell injection in command: {label}",
                            evidence=full_cmd[:200],
                            file_path=file_path,
                            server_name=name,
                            description=(f"Server '{name}' command contains pattern: {label}."),
                        )
                    )

            for flag in DANGEROUS_FLAGS:
                if flag in full_cmd:
                    result.findings.append(
                        Finding(
                            rule_id="MCP-004",
                            severity=Severity.MEDIUM,
                            category="dangerous-flag",
                            label=f"Dangerous flag: {flag}",
                            evidence=full_cmd[:200],
                            file_path=file_path,
                            server_name=name,
                            description=(
                                f"Server '{name}' uses flag '{flag}' which may "
                                "disable important security controls."
                            ),
                        )
                    )

        url = cfg.get("url", "")
        if url:
            AgentScanner._check_url(name, url, file_path, result)

        headers = cfg.get("headers", {})
        if isinstance(headers, dict):
            for hdr_key, hdr_val in headers.items():
                for label, pattern in SECRET_PATTERNS:
                    if pattern.search(str(hdr_val)):
                        result.findings.append(
                            Finding(
                                rule_id="MCP-005",
                                severity=Severity.HIGH,
                                category="secret",
                                label=f"Secret in header: {label}",
                                evidence=f"{hdr_key}: <redacted>",
                                file_path=file_path,
                                server_name=name,
                                description=(
                                    f"Server '{name}' header '{hdr_key}' "
                                    f"matches the pattern for {label}."
                                ),
                            )
                        )

    @staticmethod
    def _check_url(
        name: str,
        url: str,
        file_path: str,
        result: ScanResult,
    ) -> None:
        parsed = urlparse(url)
        local_hosts = {"localhost", "127.0.0.1", "::1"}

        if parsed.scheme == "http" and parsed.hostname not in local_hosts:
            result.findings.append(
                Finding(
                    rule_id="MCP-006",
                    severity=Severity.MEDIUM,
                    category="transport",
                    label="Unencrypted remote connection",
                    evidence=url,
                    file_path=file_path,
                    server_name=name,
                    description=(
                        f"Server '{name}' uses HTTP (not HTTPS) for remote host "
                        f"'{parsed.hostname}'."
                    ),
                )
            )

        if parsed.hostname and parsed.hostname not in local_hosts and parsed.scheme != "https":
            result.findings.append(
                Finding(
                    rule_id="MCP-007",
                    severity=Severity.HIGH,
                    category="transport",
                    label="Untrusted remote endpoint",
                    evidence=url,
                    file_path=file_path,
                    server_name=name,
                    description=(
                        f"Server '{name}' connects to remote host "
                        f"'{parsed.hostname}' without HTTPS."
                    ),
                )
            )

    @staticmethod
    def _check_raw_secrets(
        raw: str,
        file_path: str,
        result: ScanResult,
    ) -> None:
        for label, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(raw):
                line_num = raw[: match.start()].count("\n") + 1
                already_found = any(
                    f.rule_id == "MCP-002" and f.line_number == line_num for f in result.findings
                )
                if not already_found:
                    result.findings.append(
                        Finding(
                            rule_id="MCP-008",
                            severity=Severity.HIGH,
                            category="secret",
                            label=f"Secret in config text: {label}",
                            evidence=f"line {line_num}: <redacted>",
                            line_number=line_num,
                            file_path=file_path,
                            description=(
                                f"File contains text matching the pattern for "
                                f"{label} at line {line_num}."
                            ),
                        )
                    )
