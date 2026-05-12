# Testudo

> Dockerised agent runtime: a hardened container that runs an entire agent workflow end-to-end with declarative permissioning, audit logging, and rollback semantics. Comes with a CLI, a FastAPI bridge, and an Electron UI scaffold.

**Status:** v0.1.0 (vertical-slice release; demo workflow runs end-to-end). 213 tests, 90% coverage. Electron TypeScript / React migration deferred to v0.1.5.

## What it does

Testudo is a deployment unit for an agent: drop a `workflow.json` plus optional inputs into a Testudo container and the container runs the workflow to completion under strict isolation, returning outputs and a full audit trail. The `testudo` CLI runs the same workflows on the host directly (no Docker) and `testudo serve` launches a FastAPI bridge for the Electron UI to drive.

## Why "Testudo"

- **Tortoise** that carries its shell (container) wherever it goes.
- **Roman testudo** formation: legionaries (agents) interlock shields (containers) into a hardened protective barrier.
- **Slow and steady**: deterministic, careful, rollback-friendly execution.

Naming notes: [docs/naming.md](docs/naming.md).

## v0.1 vertical slice (shipped)

| Layer | v0.1 |
|---|---|
| Input | Local file upload + generic HTTPS retrieval; Google Drive scaffolded for v0.2 |
| Sanitisation | UK + international PII detection plus prompt-injection-pattern checks; agent_scanner ported from hillstar |
| Data | DuckDB by default; Databricks adapter behind `[databricks]` extra |
| Orchestration | Lightweight in-container runner speaking Hillstar's `workflow.json`; topological dependency ordering; `${...}` reference resolution |
| Runtime | Docker container with deny-by-default permissioning, full audit log, writable rollback layer |
| CLI | `testudo run`, `testudo serve`, `testudo inspect`, `testudo ui` |
| API | FastAPI bridge: `/health`, `/workflows`, `POST /runs`, `GET /runs/{id}` (bearer-token auth) |
| UI | Vanilla-JS Electron shell (chat, file upload, output panel); TS/React migration in v0.1.5 |
| Output | File writer, chat response, dashboard component spec, ticket via webhook |
| Demo | `examples/workflow-meeting-debrief.json` runs end-to-end through every layer |

## Quick start

```bash
# Install (default)
uv pip install -e .

# Install with the FastAPI bridge
uv pip install -e ".[serve]"

# Install with development tooling (pytest, ruff, mypy, fastapi for tests)
uv pip install -e ".[dev]"

# Run the demo workflow on the host
python examples/data/seed_demo.py        # seeds examples/data/demo.duckdb
testudo run examples/workflow-meeting-debrief.json \
  --inputs-json <(echo '{"transcript_path": "examples/data/transcript.md", "demo_db_path": "examples/data/demo.duckdb", "meeting_id": "M-001", "output_path": "runs/debrief.md"}')

# Or launch the FastAPI bridge for the Electron UI
testudo serve --port 8000

# Inspect a run's audit log
testudo inspect runs/<run-id>/audit.jsonl
```

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how Testudo sits inside the broader agentic pipeline (sources → input → prompt assembly → orchestration → model → output validation → outputs) and where it overlaps with [Hillstar Orchestrator](https://github.com/evoclock/hillstar-orchestrator).

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md). v0.1.5 ships the Electron TS/React migration; v0.2 adds hybrid PII (spaCy + Presidio), Google Drive, service-principal Databricks auth, async parallel execution, and dashboard embed channels.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Citation

If you use Testudo in academic work, please cite via [CITATION.cff](CITATION.cff).
