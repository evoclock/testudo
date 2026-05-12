# Changelog

All notable changes to this project will be documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Deferred to v0.1.5 (Electron TS / React migration)

- Replace `electron/{main,preload}.js` with `.ts` via `electron-vite`.
- Renderer migration: vanilla HTML to React + Tailwind + shadcn/ui + React Flow for the DAG editor.
- Wire the renderer to the FastAPI bridge with bearer-token auth via `contextBridge`.
- Vitest + Playwright UI smoke test.

### Deferred to v0.2

- Hybrid PII detection (regex + spaCy NER + Presidio + confidence-ranked merge) per the trackingplan/pii-regex-library catalogue and the Protecto "Why Regex Fails for PII Detection in Unstructured Text" pipeline. v0.1 ships regex-only with documented limitations.
- File-format exploit detection in sanitisers (PDF, Office, archive).
- Schema validation and regression diff for structured outputs.
- Async + parallel step execution in the orchestrator.
- Google Drive connector (currently a `NotImplementedError` placeholder).
- Service-principal auth for the Databricks adapter.
- Network egress allow-list enforcement at the Docker layer (v0.1 ships `--network=none`).

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
