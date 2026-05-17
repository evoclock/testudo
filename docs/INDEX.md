---
title: "Testudo docs index"
---

## Architecture + roadmap

- [ARCHITECTURE.md](ARCHITECTURE.md) -- where Testudo sits in the broader agentic pipeline, the v0.1.5 internal layers, the five defence-in-depth layers (sanitisation -> permission check -> scan-then-permit -> MCP server separation -> audit), model adapters, UI modes.
- [ROADMAP.md](ROADMAP.md) -- shipped, in-flight, v0.2 through v0.4 plans.
- [POSITIONING.md](POSITIONING.md) -- positioning against the class of restrictive enterprise agentic-platform products (Microsoft Copilot Studio as lead example, plus Vertex AI Agent Builder, Bedrock Agents, Agentforce, ServiceNow Now Assist, watsonx Orchestrate, Rovo, Glean, and similar). Today's connector gap, friction and security comparison, close-the-gap plan including rejected expansions (no-code GUI, connector marketplace, centralised tenant admin) and committed work (M365 / Slack connectors, MSAL auth, per-resource gating, compliance control mapping).

## Setup guides

- [OLLAMA_SETUP.md](OLLAMA_SETUP.md) -- install Ollama, the `:cloud` suffix convention, the 6-cloud + 4-local picker, point testudo at the daemon, use the `models.ollama_chat` tool from a workflow.
- [PACKAGING.md](PACKAGING.md) -- build a clickable `.app` (Mac) or `AppImage` (Linux) with no CLI prerequisites on the target. Covers prerequisites, PyInstaller + electron-builder sequence, smoke test, env file placement, and distribution to the corporate Mac.

## Validation

- [COMPOSE-SMOKE-TEST.md](COMPOSE-SMOKE-TEST.md) -- 4-step round-trip exercise for the Compose -> Save -> Run cycle. No external deps; exercises `connectors.local_file -> sanitisers.pii_and_injection -> outputs.file -> outputs.chat`.

## Repo-root state docs

These live at the repo root, not under `docs/`, because they're frequently rewritten:

- [../STATUS.md](../STATUS.md) -- frozen snapshot of the codebase at the v0.1.5 release.
- [../NEXT_ACTIONS.md](../NEXT_ACTIONS.md) -- next-session priorities.
- [../CHANGELOG.md](../CHANGELOG.md) -- Keep-a-Changelog format; v0.0.1 through v0.1.5.

## Environment templates

`.env.*.example` templates in the repo root. Copy to `.env.*` (gitignored), `chmod 600`, fill in real values:

- [.env.testudo.example](../.env.testudo.example) -- bridge token, URL, HMAC receipt key, repo root.
- [.env.databricks.example](../.env.databricks.example) -- workspace hostname, HTTP path, PAT.
- [.env.ollama.example](../.env.ollama.example) -- Ollama URL + optional default model.

## Test fixtures with setup READMEs

- [tests/fixtures/drive/README.md](../tests/fixtures/drive/README.md) -- three sample files to upload to a public Google Drive folder for URL-mode testing.
- [tests/fixtures/databricks/README.md](../tests/fixtures/databricks/README.md) -- two paths for Databricks integration: the built-in `samples.bakehouse` schema (fastest) and the upload-your-own-CSV path (for PII sanitiser exercise).

## Example workflows

Under `examples/` at the repo root. All loadable via the Workflow tab once `testudo serve --workflows-dir examples` is running. The `*-v015` ones are the canonical demos surfaced in the UI; the older two are kept as reference:

- `workflow-pdf-summarise.json` (v015) -- extract a document, ask Ollama to summarise, sanitise the model output, write summary, chat-respond.
- `workflow-url-fetch.json` (v015) -- HTTPS GET (public Drive URLs auto-rewrite), sanitise, write, chat-respond.
- `workflow-db-query.json` (v015) -- DuckDB SQL -> sanitise -> markdown -> chat-respond. Bundled demo db at `examples/data/demo.duckdb`.
- `workflow-databricks-query.json` (v015) -- Databricks SQL -> sanitise -> markdown -> chat-respond. Reads `DATABRICKS_*` env vars.
- `workflow-meeting-debrief.json` -- transcript + DuckDB query demo (from the v0.1 vertical slice; reference).
- `workflow-pdf-debrief.json` -- extract a document, sanitise, write debrief. No LLM in the loop (reference).

Each currently-loaded workflow ships a human-readable README at `examples/readmes/<name>.md` covering inputs, common failures, and what a healthy run looks like. The Workflow tab fetches and renders them inline as HTML (collapsible).
