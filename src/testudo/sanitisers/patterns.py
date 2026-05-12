"""
Module: testudo.sanitisers.patterns

Purpose: shared regex pattern library used by every sanitiser. UK-flavoured PII
patterns (NIN, NHS number, postcode, phone, email), prompt-injection patterns
(ignore-previous-instructions, role-hijack, safety-bypass, hidden HTML,
invisible-instruction, tool-override), shell-injection, secret, exfiltration,
and destructive-command patterns ported from the hillstar agent_scanner.

Inputs: none (module-level constants).

Outputs: tuples of ``(label, compiled_pattern)``.

Assumptions: patterns are detection-quality, not legal-grade. Some are heuristic
and produce false positives (especially the "Generic secret" pattern). Callers
must own the false-positive trade-off for their use case.
"""

from __future__ import annotations

import re

UK_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "UK National Insurance Number",
        re.compile(r"\b[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}\d{6}[A-D]{1}\b"),
    ),
    ("Email address", re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")),
    (
        "UK phone number",
        re.compile(r"\b(?:\+?44|0)\s?(?:\d\s?){9,10}\b"),
    ),
    ("NHS number", re.compile(r"\b\d{3}\s?\d{3}\s?\d{4}\b")),
    (
        "UK postcode",
        re.compile(
            r"\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b",
            re.IGNORECASE,
        ),
    ),
]

PROMPT_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "System prompt override",
        re.compile(r"(?i)ignore\s+(all\s+)?previous\s+instructions"),
    ),
    (
        "Role hijack",
        re.compile(r"(?i)you\s+are\s+now\s+(in\s+)?(maintenance|admin|root|debug)\s+mode"),
    ),
    (
        "Safety bypass",
        re.compile(
            r"(?i)(bypass|disable|override|ignore)\s+(all\s+)?(safety|security)\s+"
            r"(checks|filters|restrictions)"
        ),
    ),
    (
        "Hidden HTML instruction",
        re.compile(
            r"<!--.*?(ignore|override|execute|bypass|admin).*?-->",
            re.DOTALL,
        ),
    ),
    (
        "Invisible instruction",
        re.compile(r"(?i)(silently|secretly|without\s+(showing|telling|informing))"),
    ),
    (
        "Tool override",
        re.compile(r"(?i)(execute|run)\s+the\s+following\s+(command|tool|function)"),
    ),
]

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "AWS secret key",
        re.compile(r"(?i)(aws.?secret|secret.?access).{0,20}['\"][A-Za-z0-9/+=]{40}"),
    ),
    (
        "Anthropic API key",
        re.compile(r"sk-ant-api\d{2}-[A-Za-z0-9_\-]{20,}"),
    ),
    ("OpenAI API key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    (
        "Generic API key",
        re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}"),
    ),
    (
        "Generic secret",
        re.compile(r"(?i)(password|passwd|secret|token|credential)\s*[:=]\s*['\"][^'\"]{8,}"),
    ),
    (
        "Private key marker",
        re.compile(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),
    ),
    ("Bearer token", re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{20,}")),
]

SECRET_ENV_NAMES: set[str] = {
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "MISTRAL_API_KEY",
    "DATABASE_PASSWORD",
    "DB_PASSWORD",
    "POSTGRES_PASSWORD",
    "ADMIN_TOKEN",
    "AUTH_TOKEN",
    "SECRET_KEY",
    "PRIVATE_KEY",
    "CLIENT_SECRET",
    "API_SECRET",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "NPM_TOKEN",
}

SHELL_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Command substitution", re.compile(r"\$\(.*\)")),
    ("Backtick execution", re.compile(r"`[^`]+`")),
    ("Pipe chain", re.compile(r"\|")),
    ("Command chain (&&)", re.compile(r"&&")),
    ("Command chain (;)", re.compile(r";\s*\w")),
    ("Redirect to file", re.compile(r">\s*/\w")),
    (
        "Curl/wget exfiltration",
        re.compile(r"(?i)(curl|wget)\s+.*(http|ftp)"),
    ),
    ("Netcat listener", re.compile(r"(?i)\bnc\b.*-[lp]")),
    (
        "Read sensitive files",
        re.compile(r"(?i)cat\s+(/etc/passwd|/etc/shadow|~/\.ssh|~/\.env|~/\.aws)"),
    ),
]

DANGEROUS_FLAGS: list[str] = [
    "--no-sandbox",
    "--disable-security",
    "--allow-all",
    "--privileged",
    "--no-verify",
    "--insecure",
    "--trust-all",
]

EXFILTRATION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "SSH key access",
        re.compile(r"(?i)(~/\.ssh|\.ssh/id_rsa|\.ssh/id_ed25519|authorized_keys)"),
    ),
    (
        "AWS credential access",
        re.compile(r"(?i)(~/\.aws|\.aws/credentials|\.aws/config)"),
    ),
    ("Env file access", re.compile(r"(?i)(~/\.env|\.env\b|\.env\.local)")),
    ("Shadow file access", re.compile(r"/etc/shadow")),
    (
        "Browser data access",
        re.compile(r"(?i)(\.chrome|\.firefox|\.mozilla).*(cookie|password|login)"),
    ),
    (
        "Remote exfiltration URL",
        re.compile(
            r"(?i)(curl|wget|fetch|requests?\.(get|post))\s+.*"
            r"(https?://(?!localhost|127\.0\.0\.1)[^\s\"']+)"
        ),
    ),
    (
        "Data POST to remote",
        re.compile(r"(?i)curl\s+-X\s+POST\s+https?://(?!localhost|127\.0\.0\.1)"),
    ),
]

DESTRUCTIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Recursive delete", re.compile(r"(?i)rm\s+-rf?\s+/")),
    ("Format disk", re.compile(r"(?i)mkfs\.")),
    ("Drop database", re.compile(r"(?i)DROP\s+(DATABASE|TABLE|SCHEMA)")),
    ("Kill all processes", re.compile(r"(?i)kill\s+-9\s+-1")),
    ("Fork bomb", re.compile(r":\(\)\s*\{\s*:\|:&\s*\}")),
]
