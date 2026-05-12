# Testudo

> Dockerised agent runtime: a hardened container that runs an entire agent workflow end-to-end with declarative permissioning, audit logging, and rollback semantics. Comes with a minimal Electron UI for chat, file upload, and output rendering.

**Status:** v0.1 vertical slice in progress (two-day sprint started 2026-05-12).

## What it does

Testudo is a deployment unit for an agent: drop a `workflow.json` plus optional inputs into a Testudo container and the container runs the workflow to completion under strict isolation, returning outputs and a full audit trail.

The container embeds a lightweight workflow orchestrator so it does not need an external coordinator for end-to-end runs. For larger pipelines, [Hillstar Orchestrator](https://github.com/evoclock/hillstar-orchestrator) can invoke a Testudo container as a single DAG step via a host-side adapter; the same `Tool` and `Workflow` interfaces work in both.

## Why "Testudo"

- **Tortoise** that carries its shell (container) wherever it goes.
- **Roman testudo** formation: legionaries (agents) interlock shields (containers) into a hardened protective barrier.
- **Slow and steady**: deterministic, careful, rollback-friendly execution.

Naming notes: [docs/naming.md](docs/naming.md).

## v0.1 vertical slice (target: two days)

| Layer | v0.1 |
|---|---|
| Input | Local file upload + generic HTTPS retrieval |
| Sanitisation | PII detection plus prompt-injection-pattern checks |
| Data | DuckDB by default; Databricks adapter as swap-in |
| Orchestration | Lightweight in-container runner speaking Hillstar's `workflow.json` |
| Runtime | Docker container with deny-by-default permissioning, full audit log, writable rollback layer |
| UI | Minimal Electron shell: chat, file upload, output panel |
| Output | Inline chat response and downloadable file |

## Quick start (when v0.1 lands)

```bash
# Install
uv pip install testudo

# Run a workflow inside a Testudo container
testudo run examples/workflow-meeting-debrief.json --input transcript.md

# Or fire up the UI
testudo ui
```

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how Testudo sits inside the broader agentic pipeline (sources → input layer → prompt assembly → orchestration → model → output validation → outputs) and where it overlaps with Hillstar.

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for the v0.1-through-v0.4 plan.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Citation

If you use Testudo in academic work, please cite it via [CITATION.cff](CITATION.cff).
