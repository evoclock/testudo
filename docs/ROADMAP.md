---
title: "Testudo roadmap"
---

## Shipped

### v0.1.0 (2026-05-12) -- vertical slice

End-to-end demo workflow runs through every layer. 213 tests, 90%
coverage. Tagged locally.

Components: runtime (Docker argv builder + Dockerfile + Runner),
permissions (filesystem / network / process, deny-by-default), audit
log (JSONL), orchestrator (Hillstar-compatible `workflow.json`,
topological sort, reference resolution, `when:` predicates, tool
registry), connectors (local file, HTTPS), sanitisers (UK PII +
international + prompt-injection + agent_scanner from hillstar), data
(DuckDB default, Databricks adapter behind extra), outputs (file,
chat, dashboard, ticket), CLI, FastAPI bridge with bearer auth, vanilla-JS
Electron scaffold, demo workflow + integration test.

### v0.1.5 (2026-05-12) -- security expansion + TS/React migration

279 tests, 87% coverage. ruff clean.

- **Sanitisers**: ported 16 missing hillstar redaction patterns +
  ANTHROPIC_BASE_URL (CVE-2026-21852); ~50 country-specific PII
  patterns; hidden-unicode + comment payloads sanitiser; OWASP web
  Top 10 + OWASP MCP Top 10 detection; output-side pipeline; secrets.
- **MCP servers (in-house)**: base (JSON-RPC 2.0 / STDIO),
  llm_response_capturer (read-only, issues HMAC-signed receipts),
  file_writer (write-only, validates receipts), file_extractor
  (read-only, PDF / DOCX / PPTX / HTML / JSON / TXT).
- **Permissions**: scan-before-permit gate using the in-house
  AgentScanner; raises ScanRejected on HIGH/CRITICAL findings before
  the path-permission check.
- **Bridge**: in-house token-bucket rate limiter.
- **Electron**: TS + React + electron-vite migration; vanilla JS
  scaffold removed entirely.

### v0.1.5 follow-up (2026-05-12)

312 tests. New + dropped scope:

- **Model adapters**: `testudo.models.ollama_chat` POSTs to Ollama
  and routes the response through `sanitise_output` automatically.
- **New example workflows**: `pdf-debrief`, `pdf-summarise` (LLM in
  the loop), `url-fetch`, `db-query`.
- **UI mode picker**: five-tab renderer (File / URL / Database /
  Workflow / Compose).
- **DAG composition mode**: tool palette + editable React Flow canvas
  + node inspector; saves via `POST /workflows`. `GET /tools`
  introspects DEFAULT_REGISTRY via Python `inspect`.
- **DAG display panel** restored under each mode form; coloured by
  post-run status.
- **Drive (private)** dropped from scope. Public link-shared Drive
  files reachable via `connectors.https_get` with the direct-download
  URL form.

## In flight

### v0.1.6 -- Docker default execution path

The Docker isolation primitive is architected and scaffolded but not
the default execution path in v0.1.x. `build_docker_argv` builds the
canonical `docker run` argv from a workflow's `IsolationProfile`; the
Dockerfile produces `testudo:0.1`; `Runner` wires the audit log around
the container invocation. The CLI / FastAPI default path currently
runs the orchestrator in-process. Wiring the Docker path into
`testudo run` and `POST /runs` by default is the priority-1 item for
v0.1.6.

Also in v0.1.6:

- Wire the read-only -> sanitiser -> write-only MCP chain into the
  orchestrator. Today the three servers exist as standalone STDIO
  scripts; the orchestrator should spawn the trio for any workflow
  step that touches LLM output going to disk.
- Audit-log integration for the scan-then-permit gate.
- `RateLimitMiddleware` config via `testudo serve` CLI flags.
- `workflow-url-document-debrief`: fetch a URL, save to a temp path,
  extract_document, sanitise, write. Covers the "PDF on Drive via
  URL" case.

## Planned

### v0.2 -- depth on sanitisation + execution

- **Presidio NLP hybrid**: regex + spaCy NER + confidence merge
  behind a `[sanitisers]` extra. Adds higher-recall detection of
  names, places, and organisations that regex genuinely cannot catch.
  Install gate is the 750 MB `en_core_web_lg` spaCy model.
- **Service-principal Databricks auth.** Today the adapter only
  supports PAT.
- **Async / parallel step execution** in the orchestrator. Today
  steps run sequentially even when topologically independent.
- **Network egress allow-list enforcement at the Docker layer.** v0.1
  ships `--network=none`; v0.2 honours the per-workflow allow-list.
- **Additional model adapters**: Anthropic, OpenAI, Mistral, Groq.
  Same `models.*` shape; same sanitise-on-return invariant.
- **Output channels**: dashboard embed (Plotly Dash component),
  webhook fan-out, Slack post.

### v0.3 -- depth on validation + observability

- **File-format exploit detection**: PDF JavaScript objects, Office
  macros, archive zip-slip beyond the existing path-traversal
  patterns.
- **Schema validation + regression diff** for structured outputs.
- **LLM-as-judge** for output quality checks.
- **Audit trail visualisation** in the Electron shell.

### v0.4 -- depth on orchestration

- **Sub-workflows.**
- **Pause and resume.**
- **Retry policies** for failing steps.
- **Live run progress** in the DAG panel (streamed step status as
  steps execute, not just post-run colour).

## Post-v0.4

- **Multi-tenancy.**
- **Distributed execution across hosts.**
- **Alternative isolation primitives** (Firejail, Python-level
  sandbox) for environments without Docker.
- **Hillstar host-side adapter**: invoke a Testudo container as a
  Hillstar DAG step.
