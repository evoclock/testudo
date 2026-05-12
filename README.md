# Testudo

> Hardened agent runtime: a containerised executor that runs an entire agent workflow end-to-end with declarative permissioning, layered sanitisation, MCP server isolation, audit logging, and a typed TS/React renderer. Comes with a CLI and a FastAPI bridge.

**Status:** v0.1.5 (security expansion + Electron TS/React migration shipped). 279 tests passing, 87% coverage, ruff clean. Apache 2.0.

## What it does

Testudo is a deployment unit for an agent: a `workflow.json` declares the steps, their dependencies, the permissions each operation is allowed, and the isolation profile. Testudo loads it, sanitises every byte on input and output, gates every privileged operation through a permission check (optionally with a scan-before-permit gate), routes any LLM-side disk writes through a read-only -> sanitiser -> write-only MCP server triad with HMAC-signed receipts, and emits a per-run audit log.

## Architecture

```text
                       ┌──────────────────────────────────────┐
                       │  Electron renderer (TS + React)      │
                       │  • Sidebar (workflows)               │
                       │  • Chat                              │
                       │  • React Flow DAG preview            │
                       └──────────────┬───────────────────────┘
                                      │ window.testudo (preload contextBridge)
                                      ▼
                       ┌──────────────────────────────────────┐
                       │  FastAPI bridge (testudo serve)      │
                       │  Bearer auth + in-house rate limiter │
                       │  GET /workflows  POST /runs  ...     │
                       └──────────────┬───────────────────────┘
                                      ▼
                       ┌──────────────────────────────────────┐
                       │  Orchestrator (Executor)             │
                       │  topo-sort, ref resolution,          │
                       │  when: predicates, tool registry     │
                       └──────────────┬───────────────────────┘
                                      ▼
   ┌────────────────────┬─────────────┴────────────┬─────────────────┐
   ▼                    ▼                          ▼                 ▼
Permissions       Sanitisers                Connectors / Data    Runtime
• fs read/write   • PII (~50 countries)     • local file         • build_docker_argv
• net egress      • prompt injection        • HTTPS              • Dockerfile
• proc spawn      • OWASP web + MCP         • DuckDB             • Runner
• scan-then-      • hidden unicode          • Databricks (extra) • IsolationProfile
  permit gate     • output-side pipeline    • Drive (stub)
                  • secrets                                       Audit (JSONL)
                                                                  • workflow_start
                  In-house MCP servers                            • step_start/end
                  • llm_response_capturer (read-only)             • permission_*
                  • file_extractor (read-only)                    • error
                  • file_writer (write-only, HMAC receipts)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the layered view, the broader-pipeline positioning, and a worked example of the read-only -> sanitiser -> write-only chain.

## Why "Testudo"

- **Tortoise** that carries its shell (container) wherever it goes.
- **Roman testudo** formation: legionaries (agents) interlock shields (containers) into a hardened protective barrier.
- **Slow and steady**: deterministic, careful, rollback-friendly execution.

Naming notes: [docs/naming.md](docs/naming.md).

## v0.1.5 vertical slice (shipped)

| Layer | v0.1.5 |
|---|---|
| Input | Local file; HTTPS; document extractor (PDF / DOCX / PPTX / HTML / JSON / TXT); Google Drive scaffolded for v0.2 |
| Sanitisation | UK PII + ~50 country-specific PII; prompt injection; OWASP web Top 10; OWASP MCP Top 10; hidden-unicode + comment payloads; secrets (Hillstar parity + extras); full output-side pipeline; in-house agent scanner |
| Permissions | Filesystem read/write prefixes; network egress allow-list; process-spawn deny-by-default; scan-before-permit gate for MCP-config / skill artifacts |
| Data | DuckDB by default; Databricks adapter behind `[databricks]` extra |
| Orchestration | Hillstar-compatible `workflow.json`; topological dependency ordering; `${...}` reference resolution; `when:` predicates; tool registry |
| MCP servers | In-house base (JSON-RPC 2.0 + STDIO); read-only `llm_response_capturer` with HMAC-signed receipts; write-only `file_writer` (receipt-gated); read-only `file_extractor` |
| Runtime | Docker argv builder, `Dockerfile`, Runner, IsolationProfile (deny-by-default network, read-only root, tmpfs `/tmp`, configurable cpu / memory) |
| Audit | Append-only JSONL per run; workflow + step lifecycle + permission decisions + errors |
| CLI | `testudo run`, `testudo serve`, `testudo inspect`, `testudo ui` |
| API | FastAPI bridge: `/health`, `/workflows`, `POST /runs`, `GET /runs/{id}`; bearer-token auth; in-house token-bucket rate limiter |
| UI | Electron + TypeScript + React 18 + Tailwind + React Flow (renderer via `electron-vite`, sandboxed; bridge token flows via preload `contextBridge`) |
| Output | File writer, chat-inline, dashboard component spec, ticket via webhook |
| Demo | `examples/workflow-meeting-debrief.json` (text-mode) and `examples/workflow-pdf-debrief.json` (PDF-mode) both run end-to-end |

## Quick start

```bash
# Install (default)
uv pip install -e .

# Install with the FastAPI bridge
uv pip install -e ".[serve]"

# Install with file_ops extras (pypdf, python-docx) for PDF / DOCX extraction
uv pip install -e ".[file_ops]"

# Install with development tooling (pytest, ruff, mypy)
uv pip install -e ".[dev]"
```

### Run the demo workflows on the host

```bash
# Text-mode demo
python examples/data/seed_demo.py
testudo run examples/workflow-meeting-debrief.json \
  --inputs-json <(echo '{"transcript_path": "examples/data/transcript.md", "demo_db_path": "examples/data/demo.duckdb", "meeting_id": "M-001", "output_path": "runs/debrief.md"}')

# PDF-mode demo (drop a PDF at examples/data/sample.pdf first)
testudo run examples/workflow-pdf-debrief.json \
  --inputs-json <(echo '{"pdf_path": "examples/data/sample.pdf", "output_path": "runs/pdf-debrief.md"}')
```

### Bring up the Electron UI

Two terminals.

```bash
# terminal 1 -- bridge
cd /path/to/testudo
source .venv/bin/activate
testudo serve --port 8000
# stderr: "[testudo] bearer token: <random-url-safe>"
```

```bash
# terminal 2 -- electron
export TESTUDO_BRIDGE_URL=http://127.0.0.1:8000
export TESTUDO_BRIDGE_TOKEN=<paste-token>
cd electron && npm run dev
```

Alternative bring-up with a pinned token:

```bash
export TESTUDO_BRIDGE_TOKEN="$(openssl rand -hex 32)"
testudo serve --port 8000 --token "$TESTUDO_BRIDGE_TOKEN" &
cd electron && npm run dev
```

### Inspect a run

```bash
testudo inspect runs/<run-id>/audit.jsonl
```

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) and [NEXT_ACTIONS.md](NEXT_ACTIONS.md). v0.1.6 wires the Docker isolation path into the default `testudo run` flow. v0.2 adds the Presidio NLP hybrid (regex + spaCy NER + confidence merge), Google Drive, service-principal Databricks auth, async parallel execution, and dashboard embed channels.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Citation

If you use Testudo in academic or commercial work, please cite via [CITATION.cff](CITATION.cff).
