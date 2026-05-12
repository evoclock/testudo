---
title: "Testudo docs index"
---

## Architecture + roadmap

- [ARCHITECTURE.md](ARCHITECTURE.md) -- where Testudo sits in the broader agentic pipeline, the v0.1.5 internal layers, the five defence-in-depth layers (sanitisation -> permission check -> scan-then-permit -> MCP server separation -> audit), model adapters, UI modes.
- [ROADMAP.md](ROADMAP.md) -- shipped, in-flight, v0.2 through v0.4 plans.

## Setup guides

- [OLLAMA_SETUP.md](OLLAMA_SETUP.md) -- install Ollama, pull `minimax-m2.5`, point testudo at the daemon, use the `models.ollama_chat` tool from a workflow.

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

Under `examples/` at the repo root. All loadable via the Workflow tab once `testudo serve --workflows-dir examples` is running:

- `workflow-meeting-debrief.json` -- transcript + DuckDB query demo (from the v0.1 vertical slice).
- `workflow-pdf-debrief.json` -- extract a document, sanitise, write debrief. No LLM in the loop.
- `workflow-pdf-summarise.json` -- extract a document, ask Ollama to summarise, sanitise the model output, write summary.
- `workflow-url-fetch.json` -- HTTPS GET (public Drive URLs welcome), sanitise, write.
- `workflow-db-query.json` -- DuckDB SQL → markdown.
