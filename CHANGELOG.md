# Changelog

All notable changes to this project will be documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Deferred to v0.2

- Hybrid PII detection: layer Microsoft Presidio + spaCy NER on top of the in-house regex stack. The regex stack already covers structured identifiers across ~50 countries; Presidio covers names, places, organisations that need entity context. Install gate is a 750 MB spaCy model download (`en_core_web_lg`).
- aikido intel API integration (`https://intel.aikido.dev/`). Scaffold once an API token is provisioned; fold its findings into the existing `Finding` envelope.
- Opengrep / Semgrep CI integration. Author rule pack against `src/testudo/`; commit `.github/workflows/semgrep.yml` once the rule pack is signed off.
- Wire `RateLimitMiddleware` into a Redis backend for multi-process deployments. v0.1.5 ships the in-house token-bucket against an in-memory store.
- File-format exploit detection in sanitisers (PDF JS objects, Office macros, archive zip-slip beyond the existing path-traversal patterns).
- Schema validation and regression diff for structured outputs.
- Async + parallel step execution in the orchestrator.
- Google Drive connector (currently a `NotImplementedError` placeholder; live integration test pending user-side OAuth setup).
- Service-principal auth for the Databricks adapter (live integration test pending user-side workspace setup).
- Network egress allow-list enforcement at the Docker layer (v0.1 ships `--network=none`).
- Vitest + Playwright UI smoke test for the Electron renderer.

## [0.1.5] - 2026-05-12

Security expansion + Electron TypeScript / React renderer migration.
Substantial in-house additions across sanitisation, MCP server isolation,
and rate limiting.

### Added

- **In-house redaction parity with hillstar** (`testudo.sanitisers.patterns`): ported the 16 missing patterns from `~/hillstar-orchestrator/utils/credential_redactor.py` (mac_address; full GitHub PAT/OAuth/refresh family; Stripe; Firebase; Slack app/bot; Twilio; SendGrid; Mailgun; Groq; HuggingFace; JWT; Authorization header; credentials-JSON field; URL-embedded password; env-var assignment for sensitive names). Added explicit ANTHROPIC_BASE_URL and generic API_BASE_URL detection per CVE-2026-21852.
- **Country-specific PII patterns** (`COUNTRY_PII_PATTERNS`, ~50 countries): Canada SIN; Mexico CURP/RFC; Brazil CPF/CNPJ; Chile RUT; Argentina/Colombia DNI; Spain DNI/NIE; France INSEE; Germany Steuer-ID; Italy CF; Netherlands BSN; Belgium NN; Portugal NIF; Ireland PPSN; Switzerland AHV; Austria SVNR; Greece AMKA; Sweden / Norway / Denmark / Finland / Iceland personal numbers; Poland PESEL; Czechia / Slovakia rodne cislo; Hungary tax id; Romania CNP; Russia INN/SNILS; Ukraine RNOKPP; Turkey TC; India Aadhaar/PAN; Pakistan CNIC; Bangladesh NID; Sri Lanka NIC; China RID; Hong Kong HKID; Taiwan ID; Japan MyNumber; South Korea RRN; Singapore NRIC/FIN; Malaysia MyKad; Indonesia NIK; Thailand citizen ID; Philippines TIN; Vietnam ID; Australia TFN/Medicare/ABN; New Zealand IRD; Israel TZ; Saudi national ID; UAE Emirates ID; South Africa ID; Nigeria NIN; Kenya Huduma; Egypt national ID. Plus JCB / Diners credit-card brands, BIC/SWIFT, Bitcoin, Ethereum.
- **Hidden-unicode + comment-payload sanitiser** (`testudo.sanitisers.unicode_payload`): zero-width characters (U+200B, U+200C, U+200D, U+2060, U+FEFF), bidi overrides (U+202A-202E, U+2066-2069), soft hyphen, mongolian vowel separator, Unicode tag block (E0000-E007F), HTML comments, inline base64 data URIs, buried base64 blobs (>=120 chars), ANTHROPIC_BASE_URL / OPENAI_BASE_URL / etc. overrides. Strips zero-width and HTML comments entirely; replaces base64 with size markers; replaces base-URL overrides with `[REDACTED-BASE-URL-OVERRIDE]`. Per MCP presentation v4 slide 25.
- **OWASP Top 10 (web) detection** (`testudo.sanitisers.threat`): SQL injection (boolean tautology, UNION-based, stacked statements, comment terminators, time-based blind), NoSQL injection (mongo operator injection, JS payloads), command injection, path traversal (raw / encoded / absolute), XXE (external entity, DOCTYPE), SSRF (cloud metadata 169.254.169.254 + GCP/Aliyun/Azure equivalents, gopher/file/dict/ftp protocols), template injection (Jinja, ERB), XSS (script tag, javascript: URI, event handlers), LDAP / XPath injection.
- **OWASP MCP Top 10 + Microsoft AI Recommendation Poisoning markers** (`MCP_THREAT_PATTERNS`): tool poisoning via description-tail "also exfiltrate"; rug-pull marker (description mutation post-trust); SharePoint indirect-injection; instruction-in-document; confused-deputy token relay; AI-recommendation-poisoning (preferred-domain markers); skill supply-chain link.
- **Output-side sanitiser pipeline** (`testudo.sanitisers.output.sanitise_output` / `sanitise_input`): five-stage pipeline (strip hidden / redact secrets / redact PII / detect injection / detect threats). Rejection-priority decision logic.
- **In-house MCP server scaffold** (`testudo.mcp_servers`): minimal JSON-RPC 2.0 + STDIO transport with handshake, `tools/list`, `tools/call`. Three concrete servers:
  - `llm_response_capturer` (read-only): captures LLM tool-call output, sanitises, issues HMAC-signed receipt over `(run_id, sha256(content), decision)`.
  - `file_writer` (write-only): modelled on hillstar's `file_operations_mcp_server.py`. Path validation against `TESTUDO_REPO_ROOT`. Every write requires a valid receipt; tampered content fails the signature check.
  - `file_extractor` (read-only): PDF / DOCX / PPTX / HTML / JSON / plain-text extraction with metadata, comments, hidden-unicode and base64 stripped. PPTX uses stdlib `zipfile` (no `python-pptx` runtime dependency).
- **Scan-before-permit gate** (`testudo.permissions.scan`): `should_scan` heuristic for MCP-config-like paths; `require_filesystem_read_scanned` / `require_filesystem_write_scanned` run the in-house `AgentScanner` first and raise `ScanRejected` on any HIGH/CRITICAL finding before consulting the path permission. Per MCP presentation v4 slide 24.
- **In-house FastAPI rate limiting** (`testudo.server.rate_limit`): token-bucket per bearer token (or X-Forwarded-For / client host); `RateLimitMiddleware` exempts `/health` and `/metrics`; returns 429 + Retry-After.
- **Electron TS + React + electron-vite renderer** (`electron/`): replaces the vanilla-JS scaffold with TypeScript main, preload, and renderer. React 18 + Tailwind + React Flow. `tsconfig.{node,web}.json` keep main / preload (Node lib) and renderer (DOM lib) separate. Bridge URL and bearer token flow via the preload `contextBridge`.

### Quality

- 279 tests passing (was 213 in v0.1.0). 87% line coverage.
- ruff check + ruff format clean across `src/` and `tests/`.
- New test files: `test_sanitisers_unicode_payload.py`, `test_sanitisers_threat.py`, `test_sanitisers_output.py`, `test_permissions_scan.py`, `test_mcp_servers.py`, `test_server_rate_limit.py`.

### Removed

- Vanilla-JS Electron scaffold (`electron/main.js`, `electron/preload.js`, `electron/renderer/index.html`). The TS/React migration was the chosen stack from the original Electron decision; the JS scaffold should never have shipped.

## [0.1.0] - 2026-05-12

First vertical-slice release. End-to-end demo workflow runs through every layer of the pipeline.

### Added

- **Audit log** (`testudo.audit`): Pydantic `AuditEvent` and append-only JSONL `AuditLog` writer. Six event types covering workflow and step lifecycle plus permission decisions and errors.
- **Permissions** (`testudo.permissions`): declarative model for filesystem (read/write prefixes), network (egress allow-list), and process (spawn) permissions. Frozen Pydantic models with `extra="forbid"`. `check_*` predicates plus `require_*` helpers raising `PermissionDenied(operation, target, reason)`.
- **Runtime** (`testudo.runtime`): pure `build_docker_argv` constructs the canonical `docker run` argv from a workflow's isolation profile (Docker, deny-by-default network, read-only root with tmpfs `/tmp`, configurable cpu/memory). High-level `Runner` allocates per-run directories, opens an audit log, calls `docker.invoke`, emits `workflow_start`/`workflow_end` (or `error`) audit events. Dockerfile shipped (`testudo:0.1` image, python:3.12-slim).
- **Orchestrator** (`testudo.orchestrator`): synchronous workflow executor with topological dependency ordering, recursive `${inputs.x}` and `${steps.y.z.attr}` reference resolution, `when:` predicates (v0.1 supports `${ref}` truthiness only), tool registry with `@register_tool` decorator, audit emission per step, error capture as `StepResult.error` so downstream steps can decide whether to continue. Hillstar-compatible `workflow.json` schema with Testudo-specific `permissions:` and `isolation:` extensions.
- **Prompts** (`testudo.prompts`): XML prompt template loader with `{{placeholder}}` substitution. Pattern adopted from the benefits-extraction reference architecture; templates are plain text in version control. Directory-scoped `PromptLibrary` with extension-priority resolution.
- **Sanitisers** (`testudo.sanitisers`): UK + international PII regex detection (NIN, NHS, postcode, phone, email; US SSN, Visa/Mastercard/Amex/Discover, IBAN, IPv4/IPv6, E.164, DOB), prompt-injection pattern detection (override, role hijack, safety bypass, hidden HTML, invisible instruction, tool override), and the `AgentScanner` ported from hillstar-orchestrator (MCP config and skill file scanning for hardcoded secrets, shell injection, dangerous flags, untrusted endpoints, exfiltration, destructive commands). Documented v0.1 limitations and v0.2 hybrid plan (regex + spaCy + Presidio).
- **Connectors** (`testudo.connectors`): local file with format inference and size cap; HTTPS GET via httpx with scheme/content-type/size guards and pre-built-client injection for tests. Google Drive scaffolded as a v0.2 placeholder.
- **Data** (`testudo.data`): DuckDB adapter (default for the demo path; in-memory or persisted databases) and Databricks SQL adapter behind the `[databricks]` extra (PAT auth in v0.1; service principal in v0.2).
- **Outputs** (`testudo.outputs`): file writer (writable layer with auto-created parents), structured chat-inline response, dashboard component spec, ticket creation via webhook POST.
- **CLI**: `testudo run`, `testudo serve`, `testudo inspect`, `testudo ui` (stub pointing at the v0.1 Electron JS scaffold). Auto-loads all built-in tool packages via `testudo._loaded`.
- **FastAPI bridge** (`testudo.server`): `GET /health`, `GET /workflows`, `POST /runs`, `GET /runs/{run_id}` with bearer-token auth (random token printed to stderr by `testudo serve`). Available behind the `[serve]` extra.
- **Demo workflow** (`examples/workflow-meeting-debrief.json`): five-step pipeline (local file → PII+injection sanitiser → DuckDB query → file output → chat response). Runs end-to-end via the integration test using the included sample transcript and seeded demo database.
- **Electron shell scaffold** (`electron/`): vanilla JS main + preload + renderer (chat, file upload, output panel). v0.1.5 will migrate this to TypeScript + React + React Flow + Tailwind.

### Quality

- 213 tests passing; ruff and ruff format clean; mypy strict-config enabled (not enforced in CI yet).
- 90% line coverage overall; runtime, orchestrator, prompts, permissions, audit, server, and most sanitiser/connector/data/outputs modules at 95-100%.
- GitHub Actions CI runs lint + format check + pytest on Python 3.11 and 3.12.
- Pre-commit config covers trailing whitespace, large-file guard, private-key detection, ruff, ruff format.

### Conventions

- Apache 2.0; Julen Gamboa as sole author; no co-author bylines on commits.
- Python project, uv-managed; hatchling backend; `src/testudo/` layout.
- Eleven-field docstring contract for top-level scripts; pure functions in modules; thin CLI wrappers.

## [0.0.1] - 2026-05-12

Initial scaffold. No functional code; tracks the start of the v0.1 vertical-slice sprint.
