"""
Module: testudo.sanitisers.patterns

Purpose: shared regex pattern library used by every sanitiser. Covers UK and
international PII, country-specific national identifiers, prompt injection,
hidden-unicode and comment payloads, OWASP Top 10 injection families, MCP
threat markers (tool poisoning, rug pull, indirect prompt injection), secrets
(API keys, OAuth tokens, AWS, GitHub, Stripe, JWT, etc.), shell injection,
exfiltration, and destructive commands.

Inputs: none (module-level constants).

Outputs: tuples of ``(label, compiled_pattern)`` and module-level constants.

Assumptions: patterns are detection-quality, not legal-grade. Some are
heuristic and produce false positives (notably the Generic-secret pattern,
the dd/mm/yyyy date-of-birth, and a few country-ID variants where structure
is shared with other identifier classes). Callers own the false-positive
trade-off for their use case. Country-PII coverage is breadth-first; high
confidence regions (Canada SIN, Spanish DNI, Brazil CPF) carry checksum
hints in their patterns where feasible, but full check-digit validation is
deferred to v0.2 alongside the NER hybrid.

References:

- Hillstar credential redactor (``utils/credential_redactor.py``).
- SleekFlow data masking catalogue.
- AWS Comprehend country PII list.
- Elastic redact processor reference.
- OWASP Top 10 (web) and OWASP MCP Top 10.
- Microsoft AI recommendation poisoning blog (Feb 2026).
- MCP presentation v4 slide 25 (hidden-unicode and comment payloads).
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# UK PII
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# International PII (region-agnostic identifiers)
# ---------------------------------------------------------------------------

INTERNATIONAL_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "US SSN",
        re.compile(r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"),
    ),
    ("Credit card (Visa)", re.compile(r"\b4\d{12}(?:\d{3})?\b")),
    ("Credit card (Mastercard)", re.compile(r"\b5[1-5]\d{14}\b")),
    ("Credit card (Amex)", re.compile(r"\b3[47]\d{13}\b")),
    ("Credit card (Discover)", re.compile(r"\b6(?:011|5\d{2})\d{12}\b")),
    ("Credit card (JCB)", re.compile(r"\b35(?:2[89]|[3-8]\d)\d{12}\b")),
    ("Credit card (Diners)", re.compile(r"\b3(?:0[0-5]|[68]\d)\d{11}\b")),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    ("BIC/SWIFT code", re.compile(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b")),
    (
        "IPv4 address",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
        ),
    ),
    (
        "IPv6 address",
        re.compile(
            r"(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|"
            r"::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}|"
            r"(?:[A-Fa-f0-9]{1,4}:){1,7}:"
        ),
    ),
    (
        "MAC address",
        re.compile(r"\b(?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}\b"),
    ),
    ("E.164 phone number", re.compile(r"\+\d{8,15}\b")),
    (
        "NA phone number",
        re.compile(r"\b(?:\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b"),
    ),
    (
        "Date of birth (dd/mm/yyyy)",
        re.compile(r"\b(?:0[1-9]|[12]\d|3[01])[/-](?:0[1-9]|1[0-2])[/-](?:19|20)\d{2}\b"),
    ),
    (
        "Date of birth (yyyy-mm-dd)",
        re.compile(r"\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b"),
    ),
    ("Bitcoin address", re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")),
    ("Ethereum address", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
]

# ---------------------------------------------------------------------------
# Country-specific national identifiers
#
# Coverage is breadth-first. Where a country issues several identifiers the
# higher-risk one (national ID, tax number) is included; secondary documents
# (driver licences, passports without a check-digit format) are deferred.
# ---------------------------------------------------------------------------

COUNTRY_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # North America
    (
        "Canada SIN",
        re.compile(r"\b[1-9]\d{2}[-\s]?\d{3}[-\s]?\d{3}\b"),
    ),
    ("Mexico CURP", re.compile(r"\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b")),
    ("Mexico RFC", re.compile(r"\b[A-Z&]{3,4}\d{6}[A-Z0-9]{3}\b")),
    # Latin America
    ("Brazil CPF", re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")),
    (
        "Brazil CNPJ",
        re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"),
    ),
    ("Chile RUT", re.compile(r"\b\d{1,2}\.?\d{3}\.?\d{3}-[0-9Kk]\b")),
    ("Argentina DNI", re.compile(r"\b\d{1,2}\.?\d{3}\.?\d{3}\b")),
    ("Colombia Cedula", re.compile(r"\b\d{6,10}\b")),
    # Europe (west)
    ("Spain DNI/NIE", re.compile(r"\b[XYZ]?\d{7,8}[A-HJ-NP-TV-Z]\b")),
    ("France INSEE/NIR", re.compile(r"\b[12]\d{2}(?:0[1-9]|1[0-2])\d{2}\d{3}\d{3}\d{2}\b")),
    ("Germany Steuer-ID", re.compile(r"\b\d{2}[ ]?\d{3}[ ]?\d{3}[ ]?\d{3}\b")),
    ("Italy Codice Fiscale", re.compile(r"\b[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b")),
    ("Netherlands BSN", re.compile(r"\b\d{9}\b")),
    ("Belgium National Number", re.compile(r"\b\d{2}\.?\d{2}\.?\d{2}-?\d{3}\.?\d{2}\b")),
    ("Portugal NIF", re.compile(r"\b\d{9}\b")),
    ("Ireland PPSN", re.compile(r"\b\d{7}[A-W][A-IW]?\b")),
    ("Switzerland AHV/AVS", re.compile(r"\b756\.?\d{4}\.?\d{4}\.?\d{2}\b")),
    ("Austria SVNR", re.compile(r"\b\d{4}[ ]?(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{2}\b")),
    ("Greece AMKA", re.compile(r"\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{2}\d{5}\b")),
    # Europe (Nordics)
    ("Sweden Personnummer", re.compile(r"\b(?:19|20)?\d{6}[-+]?\d{4}\b")),
    ("Norway Fodselsnummer", re.compile(r"\b\d{6}[ ]?\d{5}\b")),
    ("Denmark CPR", re.compile(r"\b\d{6}-?\d{4}\b")),
    ("Finland HETU", re.compile(r"\b\d{6}[-+A]\d{3}[0-9A-Y]\b")),
    ("Iceland Kennitala", re.compile(r"\b\d{6}-?\d{4}\b")),
    # Europe (east + central)
    ("Poland PESEL", re.compile(r"\b\d{11}\b")),
    ("Czechia Rodne Cislo", re.compile(r"\b\d{6}/?\d{3,4}\b")),
    ("Slovakia Rodne Cislo", re.compile(r"\b\d{6}/?\d{3,4}\b")),
    ("Hungary Tax ID", re.compile(r"\b8\d{9}\b")),
    ("Romania CNP", re.compile(r"\b[1-9]\d{12}\b")),
    ("Russia INN (individual)", re.compile(r"\b\d{12}\b")),
    ("Russia SNILS", re.compile(r"\b\d{3}-?\d{3}-?\d{3}[ -]?\d{2}\b")),
    ("Ukraine RNOKPP", re.compile(r"\b\d{10}\b")),
    ("Turkey TC Kimlik", re.compile(r"\b[1-9]\d{10}\b")),
    # Asia (south)
    ("India Aadhaar", re.compile(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b")),
    ("India PAN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
    ("Pakistan CNIC", re.compile(r"\b\d{5}-?\d{7}-?\d\b")),
    ("Bangladesh NID", re.compile(r"\b\d{10,17}\b")),
    ("Sri Lanka NIC", re.compile(r"\b\d{9}[VvXx]\b|\b\d{12}\b")),
    # Asia (east + south-east)
    (
        "China Resident ID",
        re.compile(
            r"\b\d{6}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b"
        ),
    ),
    ("Hong Kong HKID", re.compile(r"\b[A-Z]{1,2}\d{6}\(?[\dA]\)?\b")),
    ("Taiwan ID", re.compile(r"\b[A-Z][12]\d{8}\b")),
    ("Japan MyNumber", re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b")),
    ("South Korea RRN", re.compile(r"\b\d{6}-?[1-4]\d{6}\b")),
    ("Singapore NRIC/FIN", re.compile(r"\b[STFG]\d{7}[A-Z]\b")),
    ("Malaysia MyKad", re.compile(r"\b\d{6}-?\d{2}-?\d{4}\b")),
    ("Indonesia NIK", re.compile(r"\b\d{16}\b")),
    ("Thailand Citizen ID", re.compile(r"\b\d-?\d{4}-?\d{5}-?\d{2}-?\d\b")),
    ("Philippines TIN", re.compile(r"\b\d{3}-?\d{3}-?\d{3}-?\d{3}\b")),
    ("Vietnam ID", re.compile(r"\b\d{9}\b|\b\d{12}\b")),
    # Oceania
    ("Australia TFN", re.compile(r"\b\d{3}[ -]?\d{3}[ -]?\d{3}\b")),
    ("Australia Medicare", re.compile(r"\b[2-6]\d{3}[ ]?\d{5}[ ]?\d[ ]?\d?\b")),
    ("Australia ABN", re.compile(r"\b\d{2}[ ]?\d{3}[ ]?\d{3}[ ]?\d{3}\b")),
    ("New Zealand IRD", re.compile(r"\b\d{2,3}-?\d{3}-?\d{3}\b")),
    # Middle East + Africa
    ("Israel TZ", re.compile(r"\b\d{8,9}\b")),
    ("Saudi Arabia National ID", re.compile(r"\b[12]\d{9}\b")),
    ("UAE Emirates ID", re.compile(r"\b784-?\d{4}-?\d{7}-?\d\b")),
    (
        "South Africa ID",
        re.compile(r"\b\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{4}[01]\d{2}\b"),
    ),
    ("Nigeria NIN", re.compile(r"\b\d{11}\b")),
    ("Kenya Huduma Namba", re.compile(r"\b\d{8,9}\b")),
    ("Egypt National ID", re.compile(r"\b[23]\d{13}\b")),
]

# ---------------------------------------------------------------------------
# Hidden-unicode and comment-payload patterns
#
# Per MCP presentation v4 slide 25: zero-width characters, bidi overrides,
# HTML comments, and buried base64 are invisible to humans but visible to
# language models. Always strip on ingest.
# ---------------------------------------------------------------------------

ZERO_WIDTH_CHARS = "​‌‍⁠﻿"
BIDI_CONTROL_CHARS = "‪‫‬‭‮⁦⁧⁨⁩"
INVISIBLE_CHARS = ZERO_WIDTH_CHARS + BIDI_CONTROL_CHARS + "­᠎"

HIDDEN_UNICODE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "Zero-width character",
        re.compile(f"[{re.escape(ZERO_WIDTH_CHARS)}]"),
    ),
    (
        "Bidi control character",
        re.compile(f"[{re.escape(BIDI_CONTROL_CHARS)}]"),
    ),
    (
        "Soft hyphen / mongolian vowel separator",
        re.compile("[­᠎]"),
    ),
    (
        "Tag Unicode block (E0000-E007F)",
        re.compile(r"[\U000e0000-\U000e007f]"),
    ),
]

COMMENT_PAYLOAD_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "HTML comment",
        re.compile(r"<!--.*?-->", re.DOTALL),
    ),
    (
        "Markdown HTML comment marker",
        re.compile(r"<!--"),
    ),
    (
        "Inline base64 data URI",
        re.compile(r"data:[\w/+\-.]+;base64,[A-Za-z0-9+/=]{40,}"),
    ),
    (
        "Buried base64 blob",
        re.compile(r"\b[A-Za-z0-9+/]{120,}={0,2}\b"),
    ),
    (
        "ANTHROPIC_BASE_URL override (CVE-2026-21852)",
        re.compile(r"ANTHROPIC_BASE_URL\s*[=:]\s*['\"]?https?://[^\s'\"]+", re.IGNORECASE),
    ),
    (
        "Generic API base URL override",
        re.compile(
            r"(?:OPENAI|MISTRAL|GOOGLE|FIREWORKS|GROQ|CLAUDE|HUGGINGFACE)_BASE_URL"
            r"\s*[=:]\s*['\"]?https?://[^\s'\"]+",
            re.IGNORECASE,
        ),
    ),
]

# ---------------------------------------------------------------------------
# Prompt injection
# ---------------------------------------------------------------------------

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
            r"<!--.*?(ignore|override|execute|bypass|admin|exfiltrate).*?-->",
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
    (
        "Instruction prelude",
        re.compile(
            r"(?i)\b(new|updated|revised)\s+(system|admin|developer)\s+(prompt|instructions)"
        ),
    ),
    (
        "Forget context",
        re.compile(r"(?i)forget\s+(everything|all|prior|previous|the\s+above)"),
    ),
    (
        "Pretend / role-play prefix",
        re.compile(
            r"(?i)\b(pretend|roleplay|act\s+as)\s+(you\s+are\s+)?(an?\s+)?(unfiltered|jailbroken|dan|developer)"
        ),
    ),
    (
        "Tool-poisoning marker (Invariant Labs pattern)",
        re.compile(r"(?i)(also|additionally)\s+(exfiltrate|forward|send|leak|copy)"),
    ),
    (
        "Indirect-injection callback",
        re.compile(
            r"(?i)\b(forward|send|email|post)\s+(this|the\s+above|all\s+content)\s+to\s+\S+"
        ),
    ),
]

# ---------------------------------------------------------------------------
# OWASP Top 10 (web) injection families
# ---------------------------------------------------------------------------

OWASP_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # SQL injection
    (
        "SQL: classic boolean tautology",
        re.compile(r"(?i)\b(or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.IGNORECASE),
    ),
    (
        "SQL: UNION-based",
        re.compile(r"(?i)\bunion\s+(all\s+)?select\b"),
    ),
    (
        "SQL: stacked statements",
        re.compile(r";\s*(?:select|insert|update|delete|drop|alter|truncate)\b", re.IGNORECASE),
    ),
    (
        "SQL: comment to terminate",
        re.compile(r"(?:--\s|#\s|/\*.*?\*/)"),
    ),
    (
        "SQL: time-based blind",
        re.compile(r"(?i)\b(sleep|pg_sleep|benchmark)\s*\(|\bwaitfor\s+delay\b"),
    ),
    # NoSQL injection
    (
        "NoSQL: mongo operator injection",
        re.compile(r"\$(?:where|regex|ne|gt|lt|gte|lte|in|nin|exists)\b"),
    ),
    (
        "NoSQL: JS payload",
        re.compile(r"(?i)\bfunction\s*\(\s*\)\s*\{[^}]*return\s+true\s*[;}]"),
    ),
    # Command injection
    (
        "Command: shell metachars in arg",
        re.compile(r"[;&|`$]\s*(?:cat|ls|wget|curl|nc|bash|sh|python|perl|ruby|php|powershell)\b"),
    ),
    (
        "Command: process substitution",
        re.compile(r"(?:<|>)\s*\([^)]*\)"),
    ),
    # Path traversal
    (
        "Path traversal: ../",
        re.compile(r"(?:\.\./|\.\.\\){2,}"),
    ),
    (
        "Path traversal: encoded",
        re.compile(r"(?:%2e%2e[%2f%5c]|%252e%252e)", re.IGNORECASE),
    ),
    (
        "Path traversal: absolute escape",
        re.compile(r"(?:\.\./|\.\.\\)+(?:etc|root|home|var|proc|sys)\b"),
    ),
    # XXE
    (
        "XXE: external entity",
        re.compile(r"<!ENTITY\s+\w+\s+SYSTEM\s+['\"]"),
    ),
    (
        "XXE: doctype with entity",
        re.compile(r"<!DOCTYPE\s+\w+\s*\[[^\]]*<!ENTITY"),
    ),
    # SSRF
    (
        "SSRF: cloud metadata",
        re.compile(
            r"169\.254\.169\.254|"
            r"metadata\.google\.internal|"
            r"100\.100\.100\.200|"
            r"metadata\.azure\.com",
        ),
    ),
    (
        "SSRF: localhost protocols",
        re.compile(r"(?i)\b(?:gopher|file|dict|ftp|ldap|jar)://"),
    ),
    # Template injection
    (
        "Template injection: Jinja-style",
        re.compile(r"\{\{\s*[a-zA-Z_][\w.]*\s*\}\}"),
    ),
    (
        "Template injection: ERB-style",
        re.compile(r"<%=?[^%]*%>"),
    ),
    # XSS
    (
        "XSS: script tag",
        re.compile(r"(?i)<script[^>]*>"),
    ),
    (
        "XSS: javascript: URI",
        re.compile(r"(?i)javascript:[^\"'\s]+"),
    ),
    (
        "XSS: event handler",
        re.compile(r"(?i)\son(?:click|load|error|mouseover|focus|blur)\s*="),
    ),
    # LDAP injection
    (
        "LDAP injection",
        re.compile(r"\(\s*\|\s*\([^)]*=\*\)|\(\s*&\s*\([^)]*=\*\)"),
    ),
    # XPath injection
    (
        "XPath injection",
        re.compile(r"(?i)['\"]?\s+(?:or|and)\s+\d+\s*=\s*\d+"),
    ),
]

# ---------------------------------------------------------------------------
# OWASP MCP Top 10 + Microsoft AI Recommendation Poisoning markers
# ---------------------------------------------------------------------------

MCP_THREAT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "Tool poisoning (description tail)",
        re.compile(
            r"(?i)(?:^|[.\n])\s*(?:also|additionally|in\s+addition)\s+"
            r"(?:exfiltrate|send|forward|leak|email|post)\b",
            re.MULTILINE,
        ),
    ),
    (
        "Rug pull marker (description mutation)",
        re.compile(
            r"(?i)description.{0,40}(updated|changed|modified)\s+(after|since)\s+(approval|trust)"
        ),
    ),
    (
        "Indirect injection: SharePoint",
        re.compile(r"(?i)sharepoint:[^/\s]+"),
    ),
    (
        "Indirect injection: instruction in document",
        re.compile(
            r"(?i)\bwhen\s+(?:you\s+)?(?:read|process|see)\s+this[,.]?\s+"
            r"(?:do|execute|run|call|invoke|forward|send|email|post|exfiltrate|leak)\b",
        ),
    ),
    (
        "Confused deputy: token relay",
        re.compile(
            r"(?i)\b(forward|relay|send)\s+(my|the|this)\s+(token|credential|api[_-]?key)\b"
        ),
    ),
    (
        "AI recommendation poisoning marker",
        re.compile(
            r"(?i)\b(recommend|suggest|prefer)\s+(only|always)\s+\S+(\.com|\.io|\.dev|\.ai|\.org)\b"
        ),
    ),
    (
        "Skill supply-chain link",
        re.compile(
            r"(?i)(?:fetch|load|import|require)\s+(?:from\s+)?https?://(?!localhost|127\.0\.0\.1)\S+"
        ),
    ),
]

# ---------------------------------------------------------------------------
# Secrets, API keys, OAuth tokens
#
# Hillstar-parity set plus the v0.1 testudo originals. ``_GENERIC`` patterns
# (api_key_generic, generic_secret) are intentionally last so more specific
# matches (anthropic, github_*, etc.) win the redaction race when both apply.
# ---------------------------------------------------------------------------

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # AWS
    (
        "AWS access key (all prefixes)",
        re.compile(r"\b(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}\b"),
    ),
    (
        "AWS secret key",
        re.compile(r"(?i)(aws.?secret|secret.?access).{0,20}['\"][A-Za-z0-9/+=]{40}"),
    ),
    # Anthropic, OpenAI, Mistral, Google, Fireworks
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI API key", re.compile(r"sk-[A-Za-z0-9_\-]{20,}")),
    ("Mistral API key", re.compile(r"\b[A-Za-z0-9]{32}\b\s*#?\s*mistral", re.IGNORECASE)),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{10,}\b")),
    (
        "Google OAuth client ID",
        re.compile(r"\b\d+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b"),
    ),
    ("Fireworks API key", re.compile(r"\bfw_[A-Za-z0-9]{10,}\b")),
    ("Groq API key", re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b")),
    ("HuggingFace token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    # GitHub
    ("GitHub PAT (classic)", re.compile(r"\bghp_[A-Za-z0-9_]{36}\b")),
    ("GitHub PAT (fine-grained)", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    ("GitHub OAuth token", re.compile(r"\bgho_[A-Za-z0-9_]{36}\b")),
    ("GitHub user-to-server token", re.compile(r"\bghu_[A-Za-z0-9_]{36}\b")),
    ("GitHub server-to-server token", re.compile(r"\bghs_[A-Za-z0-9_]{36}\b")),
    ("GitHub refresh token", re.compile(r"\bghr_[A-Za-z0-9_]{36,}\b")),
    # Other providers
    ("Stripe key", re.compile(r"\b(?:r|s)k_(test|live)_[0-9a-zA-Z]{24}\b")),
    (
        "Firebase domain",
        re.compile(r"\b[a-z0-9-]{1,30}\.firebaseapp\.com\b"),
    ),
    (
        "Slack app token",
        re.compile(r"\bxapp-[0-9]+-[A-Za-z0-9_]+-[0-9]+-[a-f0-9]+\b"),
    ),
    (
        "Slack bot/user token",
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    (
        "Twilio auth token",
        re.compile(r"\bSK[a-f0-9]{32}\b"),
    ),
    (
        "SendGrid API key",
        re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b"),
    ),
    (
        "Mailgun API key",
        re.compile(r"\bkey-[a-f0-9]{32}\b"),
    ),
    # JWT
    (
        "JSON Web Token",
        re.compile(
            r"\b(?:ey[A-Za-z0-9_\-=]{10,})\.(?:[A-Za-z0-9_\-=]{10,})\.(?:[A-Za-z0-9_\-=]{10,})\b"
        ),
    ),
    # Generic identifiers
    ("Bearer token", re.compile(r"Bearer\s+[A-Za-z0-9_\-\.~+/=]{20,}")),
    (
        "Authorization header",
        re.compile(r"(?i)(?:Authorization|X-API-Key)\s*[=:]\s*['\"]?[A-Za-z0-9\-_\.]{8,}"),
    ),
    (
        "Credentials JSON field",
        re.compile(
            r'"(?:api_key|apiKey|access_token|accessToken|password|secret|client_secret|refresh_token)"\s*:\s*"([^"]+)"',
        ),
    ),
    (
        "URL-embedded password",
        re.compile(r"(?:https?|ftp|ssh|mongodb|redis|postgres|mysql)://[^:@\s]+:[^@\s]+@"),
    ),
    (
        "Env-var assignment (sensitive name)",
        re.compile(
            r"\b(?:ANTHROPIC_API_KEY|OPENAI_API_KEY|MISTRAL_API_KEY|GOOGLE_API_KEY|"
            r"FIREWORKS_API_KEY|GROQ_API_KEY|HUGGINGFACE_TOKEN|GITHUB_TOKEN|"
            r"AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|DATABASE_PASSWORD|DB_PASSWORD)"
            r"\s*=\s*['\"]?[A-Za-z0-9\-_\.~+/=]{8,}",
            re.IGNORECASE,
        ),
    ),
    (
        "Private key marker",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ),
    # Generic catch-alls last
    (
        "Generic API key",
        re.compile(r"(?i)(api[_-]?key|apikey|api[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}"),
    ),
    (
        "Generic secret",
        re.compile(
            r"(?i)(password|passwd|secret|token|credential)\s*[:=]\s*['\"][^'\"]{8,}",
        ),
    ),
]

# ---------------------------------------------------------------------------
# Sensitive env-var names (for static config scan)
# ---------------------------------------------------------------------------

SECRET_ENV_NAMES: set[str] = {
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SESSION_TOKEN",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "MISTRAL_API_KEY",
    "GOOGLE_API_KEY",
    "FIREWORKS_API_KEY",
    "GROQ_API_KEY",
    "HUGGINGFACE_TOKEN",
    "DATABASE_PASSWORD",
    "DB_PASSWORD",
    "POSTGRES_PASSWORD",
    "MYSQL_PASSWORD",
    "REDIS_PASSWORD",
    "MONGO_PASSWORD",
    "ADMIN_TOKEN",
    "AUTH_TOKEN",
    "SECRET_KEY",
    "PRIVATE_KEY",
    "CLIENT_SECRET",
    "API_SECRET",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "DOCKER_TOKEN",
    "DATABRICKS_TOKEN",
    "STRIPE_SECRET_KEY",
    "TWILIO_AUTH_TOKEN",
    "SENDGRID_API_KEY",
}

# ---------------------------------------------------------------------------
# Shell injection
# ---------------------------------------------------------------------------

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
    (
        "Dangerous interpreter eval",
        re.compile(r"(?i)\b(eval|exec)\s+[\"'$]"),
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
    "--disable-web-security",
    "--ignore-certificate-errors",
    "--no-tls-verify",
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
    (
        "DNS exfiltration",
        re.compile(
            r"(?i)(dig|nslookup|host)\s+\S+\.(?:requestcatcher|burpcollaborator|interactsh)\."
        ),
    ),
]

DESTRUCTIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Recursive delete", re.compile(r"(?i)rm\s+-rf?\s+/")),
    ("Format disk", re.compile(r"(?i)mkfs\.")),
    ("Drop database", re.compile(r"(?i)DROP\s+(DATABASE|TABLE|SCHEMA)")),
    ("Truncate table", re.compile(r"(?i)TRUNCATE\s+(TABLE\s+)?\w+")),
    ("Kill all processes", re.compile(r"(?i)kill\s+-9\s+-1")),
    ("Fork bomb", re.compile(r":\(\)\s*\{\s*:\|:&\s*\}")),
    ("Disk wipe (dd)", re.compile(r"(?i)dd\s+if=/dev/(?:zero|random|urandom)\s+of=/dev/[shvn]d")),
    ("Iptables flush", re.compile(r"(?i)iptables\s+-F")),
]

# ---------------------------------------------------------------------------
# Aggregations
# ---------------------------------------------------------------------------

ALL_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = (
    UK_PII_PATTERNS + INTERNATIONAL_PII_PATTERNS + COUNTRY_PII_PATTERNS
)
"""All PII patterns (UK + international + country-specific) in priority order."""

ALL_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = (
    PROMPT_INJECTION_PATTERNS + OWASP_INJECTION_PATTERNS + MCP_THREAT_PATTERNS
)
"""Every injection-style detector (prompt + OWASP + MCP-specific)."""
