# Testudo

<p align="center">
  <img src="assets/Testudo_80s-trans-tight.png" alt="Testudo" width="240">
</p>

> Hardened agent runtime: a containerised executor that runs an entire agent workflow end-to-end with declarative permissioning, layered sanitisation, MCP server isolation, audit logging, and a typed TS/React renderer. Comes with a CLI and a FastAPI bridge.

**Status:** v0.1.5 + in-tree follow-ups (Electron UX hardening, Databricks adapter, env-check badges, resizable panes, per-workflow READMEs + starters, collapsible help sections, chat-channel surfacing in Activity, custom DAG node template, collapsed Activity entries, two-tier header with wordmark, Socket Firewall install discipline). 316 tests passing, 84% coverage, ruff clean. Apache 2.0.

## Development disclosure

Testudo is designed and developed by Julen Gamboa. As part of the implementation process I use AI assistance (Claude Code and
Ollama-served local models) as team members to whom I assign sprint tasks in the same way you would with any dev team. Every step of the process is human-gated: design and code review precede commits. My position is one of low/no-trust and everything is either delivered according to the definition-of-done or it is rejected.

No agent performs wholesale codebase management. All package installs are routed through Socket Firewall, and the full
audit trail (git history, code review, sanitiser test corpus) is the
intended substrate for trust rather than the AI assistance itself. The
runtime's hardening primitives (defence-in-depth sanitisers, isolation
profile, MCP-server separation, audit log) are designed against the same
threat model that AI-assisted development often produces in adjacent/comparable tooling out there.

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
  permit gate     • output-side pipeline
                  • secrets                                       Audit (JSONL)
                                                                  • workflow_start
                  In-house MCP servers                            • step_start/end
                  • llm_response_capturer (read-only)             • permission_*
                  • file_extractor (read-only)                    • error
                  • file_writer (write-only, HMAC receipts)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the layered view, the broader-pipeline positioning, and a worked example of the read-only -> sanitiser -> write-only chain.

## What Testudo is and is not

**Testudo is:**

- A hardened agent runtime: container-isolated execution of declarative workflows with defence-in-depth sanitisation on every byte of input and output.
- A multi-provider, multi-MCP host (in-house). The model adapter layer is built around `models.<provider>` tools; today `models.ollama_chat` is the shipped adapter, with Anthropic / OpenAI / Mistral / Google adapters planned for v0.2 under the same shape and the same sanitise-on-return invariant. The MCP server layer is in-house only (no third-party MCP server hosting); we ship `llm_response_capturer`, `file_writer`, and `file_extractor` and will add more in-house servers behind the same security boundary as needed.
- A workflow composer with a graph editor (the **Compose** tab). Drag tools from a palette, wire `needs:` edges on a React Flow canvas, edit per-step `with:` params in the inspector, save as a workflow JSON via `POST /workflows`. The composer covers the same workflow shape Testudo executes; advanced authoring (sub-workflows, looping, branching beyond `when:` predicates) is intentionally deferred to Hillstar.

**Testudo is not:**

- A replacement for a full-fledged workflow orchestrator. Tools like Hillstar, Airflow, Prefect, Dagster, Temporal, Argo Workflows, and similar handle the orchestration surface above what Testudo covers: sub-workflows, retries, distributed execution across hosts, complex scheduling, long-running pipelines, host-side dispatch, graph visualisation at the pipeline scale. Testudo is deliberately scoped to single-graph workflows that fit inside one container with a clear isolation profile. Larger pipelines can stitch Testudo-like containers and tools together as steps of whichever orchestrator you already run; Hillstar is the canonical example because its `workflow.json` shape matches Testudo's, but the integration is not Hillstar-specific.
- A multi-tenant orchestrator. One runtime per machine in v0.x; multi-tenancy is scoped post-v0.4.
- An MCP server host in the Claude-Code / Cursor / Codex sense. Testudo ships its own in-house MCP servers as the security boundary; it does not surface arbitrary third-party MCP servers from the user's local config.
- A no-code agent builder. Testudo offers **low-code** authoring through the Compose canvas: drag tools from a palette, wire them with `needs:` edges, edit per-step params, save as a workflow JSON. You do not need to know how to write Python code, but you do need to understand what each step does (which connectors touch the network, what each sanitiser pass means, how the isolation profile bounds the blast radius). Agentic failure modes are subtle: silent data leaks, prompt-injection chains, output that looks right but isn't. Low-code removes the typing burden, not the understanding burden. The author owns the system-design responsibility; the proposition that "anyone can build an agent" tends to push that cost onto whoever consumes the bad outputs or has to fix the tool.

## Aim: less friction than Copilot Studio, no less secure

Testudo's target use case is **a single technical operator or small
team that needs auditable, sandboxed, declarative agentic workflows on
locked-down infrastructure**, where the friction of Microsoft Copilot
Studio (Azure subscription, Power Platform licensing, tenant admin
approval, vendor lock-in, opaque content moderation) is not warranted
but the security posture must be at least as good or better.

The default workflow shape is:

```text
SharePoint or local file -> sanitise (input side)
                         -> model call (Ollama local, or v0.2 multi-provider)
                         -> sanitise (output side: hidden-unicode strip,
                            secret redact, PII redact across ~50 country
                            patterns, prompt-injection detect, OWASP web
                            and OWASP MCP threat detect)
                         -> post to Teams / Slack / SharePoint / dashboard
```

Today the runtime, sandbox, sanitiser, and audit layers are shipped.
The M365 + Slack connectors are the missing piece; they are the v0.1.7
release-milestone scope. Access control is **not** mediated by a
centralised Testudo tenant admin: each external resource (SharePoint
site, Teams channel, Slack workspace) is gated at its own admin layer
(Entra ID app registration consent, Slack workspace app approval).
This is a deliberate architectural choice; see
[docs/POSITIONING.md](docs/POSITIONING.md) for the full
positioning, gap analysis, and close-the-gap plan (drag-drop GUI,
M365 auth, compliance attestations, per-resource gating).

## v0.1.5 vertical slice (shipped)

| Layer | v0.1.5 |
|---|---|
| Input | Local file; HTTPS; document extractor (PDF / DOCX / PPTX / HTML / JSON / TXT); Google Drive scaffolded for v0.2 |
| Sanitisation | UK PII + ~50 country-specific PII; prompt injection; OWASP web Top 10; OWASP MCP Top 10; hidden-unicode + comment payloads; secrets (Hillstar parity + extras); full output-side pipeline; in-house agent scanner |
| Permissions | Filesystem read/write prefixes; network egress allow-list; process-spawn deny-by-default; scan-before-permit gate for MCP-config / skill artifacts |
| Data | DuckDB by default; Databricks adapter behind `[databricks]` extra |
| Orchestration | Hillstar-compatible `workflow.json`; topological dependency ordering; `${...}` reference resolution; `when:` predicates; tool registry |
| Model adapters | `models.ollama_chat` against an Ollama-served model (default `minimax-m2.7:cloud` in the UI; cloud-served models use the `:cloud` suffix); response auto-routed through `sanitise_output` before return. Multi-provider planned for v0.2 (Anthropic / OpenAI / Mistral / Groq under the same `models.*` shape). |
| Prompt templates | `testudo.prompts.PromptTemplate` loads XML-shaped templates with `{{placeholder}}` substitution and `strict=True` unresolved-placeholder detection. Sample template at `examples/prompts/meeting_debrief.xml`. Orchestrator wiring (workflow steps referencing templates by name rather than embedding XML inline) is in flight for v0.1.6. |
| MCP servers | In-house base (JSON-RPC 2.0 + STDIO); read-only `llm_response_capturer` with HMAC-signed receipts; write-only `file_writer` (receipt-gated); read-only `file_extractor` |
| Runtime | Docker argv builder, `Dockerfile`, Runner, IsolationProfile (deny-by-default network, read-only root, tmpfs `/tmp`, configurable cpu / memory) |
| Audit | Append-only JSONL per run; workflow + step lifecycle + permission decisions + errors |
| CLI | `testudo run`, `testudo serve`, `testudo inspect`, `testudo ui` |
| API | FastAPI bridge: `/health`, `/workflows`, `POST /runs`, `GET /runs/{id}`; bearer-token auth; in-house token-bucket rate limiter |
| UI | Electron + TypeScript + React 18 + Tailwind + React Flow (renderer via `electron-vite`, sandboxed; bridge token flows via preload `contextBridge`) |
| Output | File writer, chat-inline, dashboard component spec, ticket via webhook |
| Demo workflows | `pdf-summarise-v015` (extract + LLM + sanitise + chat-respond), `url-fetch-v015` (HTTPS + sanitise + chat-respond), `db-query-v015` (DuckDB + sanitise + chat-respond), `databricks-query-v015` (Databricks SQL + sanitise + chat-respond), plus `meeting-debrief` / `pdf-debrief` as legacy reference. Each currently-loaded workflow ships a README under `examples/readmes/` surfaced in the Workflow tab. |
| UI modes | Five-tab picker (File / URL / Database / Workflow / Compose). File runs `pdf-summarise-v015` against a chosen Ollama model (cloud-served `minimax-m2.7:cloud` default, plus 6 alternatives in the picker). URL runs `url-fetch-v015` with auto-rewrite of Drive share URLs. Database routes to `db-query-v015` (DuckDB, bundled demo db at `examples/data/demo.duckdb`) or `databricks-query-v015` (when `DATABRICKS_*` env vars are exported). Workflow renders any workflow's input schema as a form, surfaces its README, and ships starter buttons that pre-fill known-working inputs. Compose authors workflows visually (tool palette, React Flow canvas, node inspector, save via `POST /workflows`). DAG panel shows the staged workflow's step graph with post-run OK/FAIL/SKIP colour; Activity panel renders the workflow's chat-channel output prominently alongside any per-run note. |
| UI shell | Header surfaces bridge state (`stopped`/`starting`/`online`/`error`), bridge port, version, and live env-check badges (`ollama up/down`, `databricks ready/n/a`) sourced from `GET /env-check`. The renderer/DAG/Activity split is fully resizable via drag handles (`react-resizable-panels`). Starter-query and schema-hint sections are collapsible so first-time users get guidance and repeat users get pane space. |

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
# DuckDB demo (no network, no LLM, exercises the sanitiser end-to-end)
python examples/data/seed_demo.py   # idempotent; commits a fresh demo.duckdb
testudo run examples/workflow-db-query.json \
  --inputs-json <(echo '{"database_path": "examples/data/demo.duckdb", "query": "SELECT name, role FROM attendees WHERE meeting_id = '"'"'M-001'"'"'", "parameters": [], "output_path": "runs/db-query.md"}')

# PDF summarise (needs an Ollama-served model; defaults to minimax-m2.7:cloud)
testudo run examples/workflow-pdf-summarise.json \
  --inputs-json <(echo '{"pdf_path": "examples/data/sample.md", "model": "minimax-m2.7:cloud", "output_path": "runs/pdf-summarise.md"}')

# URL fetch (public HTTPS; Drive share URLs auto-rewrite to direct-download form)
testudo run examples/workflow-url-fetch.json \
  --inputs-json <(echo '{"url": "https://raw.githubusercontent.com/evoclock/hillstar-orchestrator/main/README.md", "output_path": "runs/url-fetch.md", "max_bytes": 10485760}')

# Databricks query (needs DATABRICKS_SERVER_HOSTNAME / HTTP_PATH / TOKEN exported;
# uv pip install -e ".[databricks]" first)
testudo run examples/workflow-databricks-query.json \
  --inputs-json <(echo '{"query": "SELECT * FROM samples.bakehouse.sales_transactions LIMIT 10", "parameters": [], "output_path": "runs/databricks-query.md"}')
```

Each shipped workflow has a human-readable README at `examples/readmes/<name>.md`
covering inputs, common failures, and what a healthy run looks like. The
Workflow tab in the UI fetches and renders these inline (collapsible).

### Bring up the Electron UI

**The renderer owns the bridge lifecycle.** Launch the app, click **Start bridge** in the header, work, click **Stop bridge** (or just close the window).

#### One-time setup

```bash
# Python side
uv pip install -e ".[serve]"

# Renderer side
cd electron && npm install && cd ..
```

#### Launch the renderer

```bash
cd electron && npm run dev
```

The Electron window opens with the bridge **stopped**. In the header:

- **Start bridge** -- main process spawns `testudo serve` as a subprocess, captures the bearer token from its stderr, and forwards it to the renderer via IPC. Status badge goes yellow (`starting`) then green (`online :8000`).
- **Stop bridge** -- SIGTERM the subprocess; status badge returns to grey.
- **Close the window** -- bridge subprocess is killed automatically; no orphans.

The bridge token never appears in renderer-inspectable scope; it lives in the Electron main process and is only released to the renderer through the explicit `window.testudo.bridge.status()` IPC return value.

#### Alternative: CLI-driven turnkey (`testudo ui`)

If you prefer a single shell command instead of launching the renderer first:

```bash
source .venv/bin/activate
testudo ui                      # spawns bridge AND renderer; Ctrl-C tears both down
testudo ui --port 9000          # custom bridge port
testudo ui --no-renderer        # bridge-only mode
```

#### Manual two-terminal flow (renderer-in-isolation debugging)

```bash
# terminal 1 -- bridge
testudo serve --port 8000 --workflows-dir examples
# stderr: "[testudo] bearer token: <random-url-safe>"

# terminal 2 -- renderer (env vars pre-load the token so the in-app
# Start button is unnecessary)
export TESTUDO_BRIDGE_URL=http://127.0.0.1:8000
export TESTUDO_BRIDGE_TOKEN=<paste-token>
cd electron && npm run dev
```

### Inspect a run

```bash
testudo inspect runs/<run-id>/audit.jsonl
```

## Supply-chain hardening for users

On 2026-05-13, 84 malicious versions of `@tanstack/*` npm packages
(across 42 packages) were published with valid SLSA provenance
signatures, including a dead-man's-switch payload that wipes `~/` if the
exfiltrated GitHub token is revoked. Testudo's host was unaffected
(no `@tanstack/*` in its dependency tree), but the incident motivated a
permanent install discipline that we recommend every user and contributor adopt.

**Install-time gate.** Every package install across every package
manager must be wrapped with [Socket Firewall](https://docs.socket.dev/docs/socket-firewall-free)
(`sfw`):

```bash
npm i -g sfw     # one-time bootstrap
sfw npm install  # not bare npm install
sfw uv add foo   # not bare uv add
sfw pip install bar
```

`sfw` proxies the package manager invocation, scans the package + its
transitive dependencies against Socket's threat intel, and aborts on
known-malicious tarballs. Free, no signup, no API key.

**Don't put install commands inside scripts.** A PreToolUse Claude Code
hook can intercept `npm install` typed at the prompt and force the `sfw`
wrap, but it cannot see installs that happen inside a shell script,
Python script, or Makefile target. If a project genuinely needs scripted
dependency setup, surface the install commands in the README so the
operator runs them through `sfw` directly, rather than burying them in a
script that bypasses every install-time gate.

**Local language packs.** A long-standing convention against
geo-targeted malware: install Russian
language packs on the host. Several malware families self-abort if these
locales are present (originally documented by Krebs on Security in 2021).
On Ubuntu / Debian:

```bash
sudo apt install language-pack-ru language-pack-ru-base
```

**Lockfile + audit.** `package-lock.json` and `uv.lock` are committed.
Run `npm audit` and `pip-audit` before bumping any dependency. CI
should be the same.

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) and [NEXT_ACTIONS.md](NEXT_ACTIONS.md).

**v0.1.6 ships the containerised execution path.** `testudo run` and the
bridge's `POST /runs` will default to spawning a `docker run` invocation
built from the workflow's `IsolationProfile`. The argv builder, the
Dockerfile, and the Runner already exist; v0.1.6 wires them together,
streams container stdout / stderr back into the audit log, and marshals
inputs / outputs across the host-container boundary.

The reachability tension (workflows that legitimately need network access
to Ollama, Databricks, or public HTTPS cannot also be `--network=none`)
is the headline problem v0.1.6 solves: per-workflow egress allow-lists
declared in the `IsolationProfile`, enforced at the container's
`iptables` layer. Each workflow's README documents its own allow-list
(host + port). Where an operator's environment requires a custom
allow-list (corporate proxy, VPN, on-prem service), Testudo will ship a
small CLI helper to inspect and edit the merged ruleset before the
container starts.

**v0.2** adds the Presidio NLP hybrid (regex + spaCy NER + confidence
merge), additional in-house `models.*` adapters (Anthropic / OpenAI /
Mistral / Groq under the same shape and the same sanitise-on-return
invariant), service-principal Databricks auth, async parallel step
execution, and dashboard embed channels.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Citation

If you use Testudo in academic or commercial work, please cite via [CITATION.cff](CITATION.cff).
