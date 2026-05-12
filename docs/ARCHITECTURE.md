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
  permit gate     • output-side pipeline
                  • secrets                                       Audit (JSONL)
                                                                  • workflow_start
                  In-house MCP servers                            • step_start/end
                  • llm_response_capturer (read-only)             • permission_*
                  • file_extractor (read-only)                    • error
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

## Docker status, honestly

The Docker isolation primitive is architected and scaffolded but is not the default execution path in v0.1.5. `build_docker_argv` builds the canonical `docker run` argv from a workflow's `IsolationProfile`; the `Dockerfile` produces `testudo:0.1`; `Runner` wires the audit log around the container invocation. But the v0.1.x CLI / FastAPI default path runs the orchestrator in-process on the host. Wiring the Docker path into `testudo run` and `POST /runs` is the priority-1 item for v0.1.6 in [NEXT_ACTIONS.md](../NEXT_ACTIONS.md).

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
├── tests/              # 279 tests
├── docs/               # ARCHITECTURE, ROADMAP, INDEX, naming
├── Dockerfile          # testudo:0.1 image
├── STATUS.md           # repo state snapshot at v0.1.5
└── NEXT_ACTIONS.md     # next-session priorities
```
