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

### v0.1.5 follow-ups (2026-05-12 / 2026-05-13)

316 tests. Two waves of in-tree work on top of the v0.1.5 tag.

**Wave 1 (2026-05-12):**

- **Model adapters**: `testudo.models.ollama_chat` POSTs to Ollama and routes the response through `sanitise_output` automatically.
- **New example workflows** (renamed `*-v015`): `pdf-debrief`, `pdf-summarise` (LLM in the loop), `url-fetch`, `db-query`, `databricks-query`.
- **UI mode picker**: five-tab renderer (File / URL / Database / Workflow / Compose).
- **DAG composition mode**: tool palette + editable React Flow canvas + node inspector; saves via `POST /workflows`. `GET /tools` introspects DEFAULT_REGISTRY via Python `inspect`.
- **DAG display panel** restored under each mode form; coloured by post-run status.
- **Bridge lifecycle** in the Electron header (Start / Stop / Quit). Token isolated to main-process scope.
- **`testudo ui`** turnkey CLI; spawns bridge + renderer with shared token.
- **`GET /env-check`** endpoint + UI badges for Ollama + Databricks readiness.
- **Resizable panes** via `react-resizable-panels`.
- **Per-workflow READMEs** under `examples/readmes/` surfaced inline in the Workflow tab.
- **Starter buttons** on every run mode that pre-fill known-working inputs.
- **Collapsible help sections** (DuckDB starters, schema hint, Databricks starters, workflow starters).
- **PII regex tightening** (UK postcode strain-ID false positive fixed; Mastercard 2-series BIN range added).
- **Sanitiser tools accept structured content** (lists / dicts), JSON-encoded before regex match.

**Wave 2 (2026-05-13):**

- **Custom DAG node template** (status stripe + tool name + step id + duration row).
- **Activity panel collapsed-by-default** with chevron-expand for full meta.
- **Two-tier header** with the 80s wordmark logo on the top tier, env strip on the bottom.
- **Floating GIF inset** in the WorkflowGraph pane (pixel-art snapping turtle, rembg-processed for transparency).
- **Pre-bridge empty state** (dashed-outline panel placeholders + centred CTA card).
- **Workflow README HTML rendering** (react-markdown + remark-gfm for tables).
- **Note input on every run mode**, threaded into the Activity entry.
- **Logo asset pipeline**: 80s wordmark + full 80s logo + original turtle, all rembg + trimmed.
- **Socket Firewall install discipline**: `sfw 1.8.0` + PreToolUse hook + policy in `~/.claude/CLAUDE.md`.
- **Local language packs** (Krebs trick): Russian, Ukrainian, Chinese, Hebrew installed on host.
- **`docs/COMPOSE-SMOKE-TEST.md`**: 4-step composition spec for round-trip validation of the Compose -> Save -> Run cycle.

## In flight

### v0.1.6 -- containerised execution becomes the default

Headline release. Closes the loop on the "containerised executor" tagline.

- **Wire `docker run` into `testudo run` and `POST /runs`.** The argv builder, the Dockerfile, and the Runner already exist. v0.1.6 plumbs them: spawn the container with the `IsolationProfile`-derived argv, stream stdout / stderr back into the audit log, marshal inputs (workflow JSON + values) and outputs (audit log + written files) across the host-container boundary.
- **Per-workflow egress allow-list at the iptables layer.** Solves the reachability tension: workflows that legitimately need Ollama, Databricks, or public HTTPS declare exactly the destinations they need; the container's `iptables` ruleset enforces. No `--network=host` fallback.
- **`testudo allow-list <workflow.json>` CLI helper.** Inspects the merged allow-list (workflow declaration + operator overrides) before the container starts. Useful in restricted environments (corporate proxy, VPN, on-prem).
- **Wire the read-only -> sanitiser -> write-only MCP chain** into the orchestrator. Today the three servers exist as standalone STDIO scripts; v0.1.6 spawns the trio for any workflow step that touches LLM output going to disk.
- **Wire the prompt template assembler** into the workflow step schema. Add `template:` and `vars:` fields so steps reference named templates rather than embedding XML inline.
- **Audit-log integration for the scan-then-permit gate.**
- **`RateLimitMiddleware` config via `testudo serve` CLI flags.**
- **`workflow-url-document-debrief`**: fetch a URL, save to a temp path, extract_document, sanitise, write. Covers the "PDF on Drive via URL" case.

### v0.1.7 -- Microsoft 365 + Slack connectors + auth helper

Closes the gap to "process file -> sanitise -> post to Teams /
SharePoint / Slack" so Testudo can be deployed as a
less-friction-than-Copilot-Studio alternative on locked-down corporate
infrastructure. See [POSITIONING.md](POSITIONING.md) for
the full positioning and architectural decisions.

- **`testudo.auth.microsoft`** -- MSAL wrapper. Client-credentials flow
  (service-principal agent identity) and device-code flow (delegated
  user). Token cache in `~/.config/testudo/tokens/` with proactive
  refresh. Per-workflow scope declaration in
  `permissions.microsoft.scopes`; runtime enforces.
- **`testudo.auth.slack`** -- bot-token loader, no refresh.
- **`connectors.teams_post`** -- Microsoft Graph
  `/teams/{id}/channels/{id}/messages` (text and adaptive cards).
- **`connectors.sharepoint_read` / `connectors.sharepoint_write`** --
  Microsoft Graph `/sites/{id}/drives/{id}/items`.
- **`connectors.slack_post`** -- Slack `chat.postMessage` (text and
  block-kit).
- **Per-workflow resource binding** in `workflow.json`: explicit
  channel IDs, site IDs, drive IDs. Refuse to run a workflow whose
  declared resources are not granted by the loaded tokens; surface the
  missing permission scope name so the operator can request it from
  their admin (Entra ID for Microsoft, workspace admin for Slack).
- **Egress allow-list auto-extends** with `graph.microsoft.com` and
  `slack.com` when these connectors appear in a workflow.
- **`testudo m365 doctor` CLI** -- prints the Azure app registration
  walkthrough (redirect URIs, API permissions, admin consent URL).
- **Example workflows**:
  `workflow-sharepoint-summarise-teams-post.json` and
  `workflow-sharepoint-summarise-slack-post.json` with per-workflow
  READMEs.
- **Compliance scaffolds**: `docs/compliance/SOC2-control-mapping.md`,
  `docs/compliance/ISO27001-Annex-A-mapping.md`,
  `docs/compliance/FedRAMP-readiness.md`,
  `docs/compliance/GDPR-data-flow.md`. The deployer's auditor reviews
  these; Testudo enables certification, the deployer pursues it.

**Deliberately out of scope** (rejected expansions per
[POSITIONING.md](POSITIONING.md)):

- A no-code agent builder. Compose stays for technical users.
- A connector marketplace. Connectors land in `src/testudo/` under
  the same review discipline as the rest of the codebase.
- A centralised tenant admin surface. Per-resource admin gating at
  the external system (Entra ID app consent, Slack workspace
  approval) is the model.

**Realistic timeline**: 3-5 focused sessions. Splittable into
v0.1.7-alpha (auth + Teams + one demo) and v0.1.7-beta (SharePoint +
Slack + compliance scaffolds + second demo) if pressed for time.

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
