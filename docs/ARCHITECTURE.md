---
title: "Testudo architecture"
---

## Where Testudo sits in the broader agentic pipeline

Testudo is the **execution boundary** that wraps an agent's tool calls and orchestration steps under isolation. It is not the entire stack; it is one component in the broader agentic pipeline, but it is the deployment unit ("the agent") rather than a sub-component of someone else's runtime.

```text
              Sources                                Outputs
   +----------+ +----------+ +----------+    +----------+ +----------+
   | Documents| | Convers. | |  Web data|    | Records  | | Findings |
   |  PDFs    | | meetings | | scrape,  |    |  rows,   | |  facts,  |
   | contracts| |   calls  | |  feeds   |    |  fields  | | entities |
   +----+-----+ +----+-----+ +----+-----+    +----^-----+ +----^-----+
        |            |            |               |             |
        v            v            v               |             |
 +--------------------------------------+    +----+--+    +----+----+
 |             Input layer              |    |Routing|    | Actions |
 |       chat | API | scheduled job     |    | tags  |    | tickets |
 +-------------------+------------------+    +----^--+    +----^----+
                     v                            |             |
 +--------------------------------------+         |             |
 |          Prompt assembly             |    +----+-------------+----+
 |    XML templates + JSON schemas      |    |     Output validation |
 +-------------------+------------------+    |   schema, PII, diff   |
                     v                       +-----------^-----------+
 +--------------------------------------+                |
 |   Orchestration layer                |                |
 |   steps, branches, parallel          |  --------------+
 +-------------------+------------------+
                     v
 +--------------------------------------+
 |         Model layer                  |
 |  hosted | managed | self-hosted      |
 +--------------------------------------+

                    ^
                    |
   Testudo wraps the Orchestration + Model + Output validation layers
   inside a single hardened container. The container IS the agent.
```

## Two ways to use Testudo

### 1. Container as the agent (default)

Drop a `workflow.json` plus inputs into a Testudo container. The embedded orchestrator runs the workflow to completion. The container handles isolation, permissioning, audit, and rollback. Outputs come back to the host plus a full audit trail.

### 2. Testudo as a Hillstar DAG step

Larger pipelines run on [Hillstar](https://github.com/evoclock/hillstar-orchestrator). When a step needs hardened isolation (untrusted input, sensitive credentials, third-party tool execution), Hillstar invokes a Testudo container via a host-side adapter. The same `Tool` and `Workflow` interfaces work in both, so a tool written for Hillstar runs unchanged inside Testudo.

## v0.1.5 internal layers

```text
                       ┌──────────────────────────────────────────────┐
                       │  Electron renderer (TS + React)              │
                       │  Five modes: File / URL / Database /         │
                       │  Workflow / Compose                          │
                       │  Two-tier header: 80s wordmark logo +        │
                       │  Start/Stop/Quit + bridge status badge       │
                       │  on top tier; env-check strip (ollama,       │
                       │  databricks bullet badges) on bottom tier    │
                       │  DAG panel: custom node template (status     │
                       │  stripe + tool/id stack + duration row)      │
                       │  + floating GIF inset top-right              │
                       │  Activity panel: collapsed-by-default        │
                       │  one-line strips with chevron-expand to      │
                       │  note + chat-channel block + step list +     │
                       │  audit-log path                              │
                       └──────────────┬───────────────────────────────┘
                                      │ window.testudo.bridge.{status,start,stop}
                                      │ (preload contextBridge -- token never
                                      │  reaches renderer except via status())
                                      ▼
                       ┌──────────────────────────────────────────────┐
                       │  Electron main (Node)                        │
                       │  BridgeManager owns the testudo serve        │
                       │  subprocess: spawn, capture token from       │
                       │  stderr, poll /health, SIGTERM on quit       │
                       └──────────────┬───────────────────────────────┘
                                      ▼
                       ┌──────────────────────────────────────────────┐
                       │  FastAPI bridge (testudo serve)              │
                       │  Bearer auth + in-house rate limiter         │
                       │  GET /workflows  GET /tools  GET /env-check  │
                       │  POST /runs     POST /workflows  ...         │
                       └──────────────┬───────────────────────────────┘
                                      ▼
                       ┌──────────────────────────────────────────────┐
                       │  Orchestrator (Executor)                     │
                       │  topo-sort, ref resolution,                  │
                       │  when: predicates, tool registry             │
                       └──────────────┬───────────────────────────────┘
                                      ▼
 ┌─────────────┬──────────────┬─────────────┬────────────┬────────────┬────────────┐
 ▼             ▼              ▼             ▼            ▼            ▼            ▼
Permissions   Sanitisers   Connectors     Data        Models     Prompts      Runtime
• fs read/    • PII (~50   • local_file   • DuckDB    • ollama   • XML        • build_docker_argv
  write       countries)   • https_get    • Databricks  _chat      template   • Dockerfile
• net egress  • prompt     • extract_       (extra)               • {{var}}   • Runner
• proc spawn  injection      document    Outputs                    subst.    • IsolationProfile
• scan-then-  • OWASP web                 • file                  • strict
  permit      + MCP                       • chat                    unresolved
  gate        • hidden                    • dashboard      Audit (JSONL)        check
              unicode                     • ticket         • workflow_start
              • output-side                                • step_start/end
              pipeline                                     • permission_*
              • secrets                                    • error

In-house MCP servers (subprocess STDIO):
• llm_response_capturer (read-only)   • file_extractor (read-only)
• file_writer (write-only, HMAC receipts)
```

## The five defence-in-depth layers

Every byte that crosses into a privileged operation traverses these layers, in order. None of them are bypassable from inside a workflow step.

### 1. Input sanitisation at the workflow boundary

Triggered when a connector or upstream step produces text destined for an LLM or for downstream processing. `sanitise_input` (alias of `sanitise_output`) runs the same five-stage pipeline:

```text
content
  ↓
strip_hidden       (zero-width, bidi, HTML comments, base64, ANTHROPIC_BASE_URL)
  ↓
redact_secrets     (~50 secret pattern types; Hillstar parity + extras)
  ↓
redact_pii         (UK + international + ~50 country-specific identifiers)
  ↓
detect_injection   (system-prompt override, role hijack, safety bypass, ...)
  ↓
detect_threats     (OWASP web Top 10 + OWASP MCP Top 10)
  ↓
SanitisationResult(decision: accept | redact | reject, content, findings)
```

Rejection-priority decision: any injection or OWASP/MCP finding short-circuits to `reject`; any earlier-stage finding produces `redact`; clean content yields `accept`.

### 2. Permission check before any privileged operation

`Permissions` is a frozen Pydantic model with three sub-models (filesystem read/write prefixes, network egress allow-list, process-spawn boolean). Every privileged operation calls `require_*`; denial raises `PermissionDenied(operation, target, reason)` and the audit log captures the rejection. Deny-by-default everywhere.

### 3. Scan-before-permit gate (optional, opt-in)

For paths matching the supply-chain heuristic (`.mcp.json`, `.claude.json`, `claude_desktop_config.json`, `*.md` under `.claude/` / `.cursor/` / `.windsurf/` / `skills/`, anything with "skill" in the name) `require_filesystem_read_scanned` runs the in-house `AgentScanner` first. Any HIGH / CRITICAL finding raises `ScanRejected` before the path permission check is consulted.

### 4. MCP server separation (LLM-output side)

The single most security-relevant invariant: **anything an LLM emits passes through a read-only capturer + sanitiser before reaching a write-only file_writer**.

```text
  LLM tool-call output
        │
        ▼
  ┌──────────────────────────────────────┐
  │  llm_response_capturer (read-only)   │   has no filesystem-write capability
  │  • run sanitise_output()             │
  │  • issue HMAC-signed receipt over    │
  │    (run_id, sha256(content),         │
  │     decision)                        │
  └──────────────┬───────────────────────┘
                 │ {decision, content, findings, receipt}
                 ▼
  ┌──────────────────────────────────────┐
  │  file_writer (write-only)            │   only server with write capability
  │  • path validated against REPO_ROOT  │
  │  • receipt signature verified        │
  │  • rejected-decision -> 401          │
  │  • tampered-content -> 401           │
  └──────────────┬───────────────────────┘
                 ▼
              disk write
```

Both servers speak JSON-RPC 2.0 over STDIO (process boundary as the isolation unit). The HMAC signing key (`TESTUDO_RECEIPT_KEY`) is generated per workflow run and exported to both subprocesses; the receipt is not portable across runs.

A third in-house server, `file_extractor`, is symmetrically read-only and handles document extraction (PDF / DOCX / PPTX / HTML / JSON / TXT) on the *input* side. Its output is sanitised via `strip_hidden` before returning.

### 5. Per-run audit log

Append-only JSONL at `runs/<run_id>/audit.jsonl`. Six event types: `workflow_start`, `workflow_end`, `step_start`, `step_end`, `permission_*` (granted / denied), `error`. Every permission decision and every step boundary is captured. `testudo inspect <audit.jsonl>` pretty-prints the timeline.

## Model adapters

`testudo.models` ships one adapter in v0.1.5: `models.ollama_chat`. It POSTs to a local (or remote) Ollama-served model and routes the response through `sanitise_output` before returning to the orchestrator. Every LLM call therefore inherits the full output-side sanitiser pipeline at no per-workflow cost.

```text
workflow step (uses: models.ollama_chat)
       │
       ▼
   httpx POST /api/chat
       │
       ▼
   raw response text
       │
       ▼
   sanitise_output(raw)
       │  hidden → secrets → PII → injection → OWASP/MCP
       ▼
   {decision, content, findings, raw_length, sanitised_length}
```

The default base URL is `http://localhost:11434` (overridable via `TESTUDO_OLLAMA_URL`). Default model in the bundled `workflow-pdf-summarise` is `mistral`; the File-mode UI surfaces four recommended models (`mistral`, `minimax-m2.5`, `jan-code-4b`, `chandra-ocr-2`) plus a free-text field for any other model accessible via `ollama list`. The bridge's `GET /env-check` endpoint reports which of the four are currently installed locally so the UI can mark each one `installed` or `pull`. v0.2 adds adapters for other providers behind the same `models.*` namespace.

## UI modes (Electron renderer)

Five tabs at the top of the renderer:

- **File** — pick a local document, run the bundled `pdf-summarise` workflow (extract → ollama → write → respond).
- **URL** — paste any HTTPS URL (including public Google Drive direct-download links), run `url-fetch`.
- **Database** — DuckDB query against a path you point to; Databricks toggle ready (disabled until the env vars are exported).
- **Workflow** — pick any workflow on disk, the panel renders a dynamic form from its `inputs:` schema and submits the run.
- **Compose** — author a workflow visually. Tool palette on the left (drag a tool onto the canvas to add a node), React Flow editable canvas in the middle (drag from one node to another to add a `needs` edge), node inspector on the right (rename step IDs, edit each `with:` param, delete nodes). Save writes the resulting JSON via `POST /workflows`; the saved workflow appears in the Workflow tab.

A DAG panel sits under each mode's input form. It shows the staged workflow's step graph and colours nodes by post-run status (`OK` green, `FAIL` red, `SKIP` grey, pending muted).

## Workflow format

Testudo speaks Hillstar's `workflow.json` and adds two Testudo-specific blocks:

```json
{
  "name": "meeting-debrief",
  "steps": [...],
  "permissions": {
    "filesystem": {"read": ["/data"], "write": ["/runs"]},
    "network": {"egress": ["api.example.com"]},
    "process": {"spawn": false}
  },
  "isolation": {
    "primitive": "docker",
    "image": "testudo:0.1",
    "cpu": "1.0",
    "memory": "2g",
    "rollback": true
  }
}
```

A workflow without `permissions` and `isolation` blocks runs under deny-by-default permissions and Testudo's default isolation profile.

## What Testudo is NOT

- A multi-provider LLM library. Testudo containers either (a) call out to Hillstar for provider routing, or (b) bind one specific provider at image build time.
- An MCP server host in the Claude-Code / Cursor sense. Testudo ships its *own* in-house MCP servers as the security boundary; it does not surface arbitrary third-party MCP servers.
- A DAG visualiser. Hillstar generates Mermaid diagrams; testudo's React Flow renderer is a workflow preview, not a graph editor.
- A multi-tenant orchestrator. One runtime per machine in v0.x.
- A general-purpose sandbox. Testudo is shaped for *agent* execution: tool-call patterns, structured workflow steps, audit trails. A general-purpose Linux sandbox is a different product.

## Docker status

The Docker isolation primitive is architected and scaffolded but is not the default execution path in v0.1.5. `build_docker_argv` builds the canonical `docker run` argv from a workflow's `IsolationProfile`; the `Dockerfile` produces `testudo:0.1`; `Runner` wires the audit log around the container invocation. The v0.1.x CLI / FastAPI default path runs the orchestrator in-process on the host. v0.1.6 wires the Docker path into `testudo run` and `POST /runs` as the default, plus per-workflow egress allow-lists at the container's `iptables` layer. See [NEXT_ACTIONS.md](../NEXT_ACTIONS.md) Priority 0.

## Connector / auth layer (v0.1.7 forward-looking)

The connector library today covers local file I/O, generic HTTPS, document extraction, DuckDB, Databricks, Ollama, plus four output channels (file, chat, dashboard spec, ticket via webhook). The v0.1.7 milestone adds Microsoft 365 and Slack:

- `testudo.auth.microsoft` (new package): MSAL wrapper supporting both client-credentials (service-principal agent identity) and device-code (delegated user) flows. Token cache file-based and gitignored at `~/.config/testudo/tokens/` with proactive refresh.
- `testudo.auth.slack` (new package): static bot-token loader, no refresh.
- `connectors.teams_post`, `connectors.sharepoint_read`, `connectors.sharepoint_write`, `connectors.slack_post` use the same shape as the existing Databricks / Ollama connectors and run their output through `sanitise_output` before the network call.
- Per-workflow resource binding (channel IDs, site IDs, drive IDs) in `workflow.json`; runtime refuses to start a workflow whose declared resources are not granted by the loaded tokens and surfaces the missing-scope name to the operator.
- Access control is gated at the external resource (Entra ID app consent for Microsoft, workspace admin approval for Slack), not at a Testudo-internal admin surface. The architectural rationale and the close-the-gap plan against the wider class of vendor agent platforms is in [POSITIONING.md](POSITIONING.md).

## Repo layout

```text
testudo/
├── src/testudo/
│   ├── audit/          # JSONL append-only event log
│   ├── connectors/     # local file, HTTPS, document extractor
│   ├── data/           # DuckDB, Databricks
│   ├── mcp_servers/    # base, capturer, writer, extractor
│   ├── orchestrator/   # Executor, registry, workflow.json loader
│   ├── outputs/        # file, chat, dashboard spec, ticket
│   ├── permissions/    # model, enforce, scan
│   ├── prompts/        # XML template library
│   ├── runtime/        # docker argv builder, Runner, IsolationProfile
│   ├── sanitisers/     # PII, injection, OWASP/MCP threat, hidden-unicode,
│   │                   # output pipeline, agent scanner, secrets
│   └── server/         # FastAPI app, auth, rate limit
├── electron/           # TS + React + electron-vite renderer
├── examples/           # demo workflows + sample data
├── tests/              # 316 tests, 84% coverage
├── docs/               # ARCHITECTURE, ROADMAP, INDEX, POSITIONING,
│                       # OLLAMA_SETUP, COMPOSE-SMOKE-TEST
├── Dockerfile          # testudo:0.1 image
├── .pre-commit-config.yaml  # ruff format + ruff + mypy + detect-private-key
├── STATUS.md           # repo state snapshot
├── CHANGELOG.md        # release history
└── NEXT_ACTIONS.md     # next-session priorities
```
