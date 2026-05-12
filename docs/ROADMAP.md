---
title: "Testudo roadmap"
---

## v0.1 (vertical slice; two-day sprint started 2026-05-12)

A thin slice through every layer of the broader pipeline at minimum-viable depth, so the demo is end-to-end from day one.

### Day 1

- Repo scaffold complete (this commit).
- `runtime/`: Docker subprocess wrapper with namespaces, cgroup limits, deny-by-default networking.
- `permissions/`: declarative model in YAML or JSON plus runtime enforcement (filesystem read/write, network egress allow-list, process spawn allow/deny).
- `audit/`: JSONL audit log writer; one record per invocation capturing PID, parameters, stdio, runtime, exit status, permission decisions.
- `orchestrator/`: lightweight workflow runner speaking Hillstar's `workflow.json` with `permissions:` and `isolation:` extensions; supports sequential, branches, and simple async-parallel steps.
- Tests for runtime, permissions, audit, orchestrator (target ~80 percent coverage on these four).

### Day 2

- `connectors/`: local file upload and generic HTTPS retrieval.
- `sanitisers/`: PII detection (regex + lightweight NER via spaCy or Presidio) and prompt-injection-pattern checks.
- `data/`: DuckDB adapter (default) and a Databricks adapter scaffold (PAT auth in v0.1).
- `outputs/`: file writer and structured chat-response.
- `cli.py`: `testudo run <workflow.json> --input ...`, `testudo ui`.
- `electron/`: minimal shell — chat box, file-upload panel, output panel, calls back into the CLI.
- `examples/workflow-meeting-debrief.json`: demo workflow that uploads a transcript, sanitises, queries the DuckDB demo dataset, and returns an answer plus a result file.
- Integration test: end-to-end run of the meeting-debrief workflow.
- README polish, ARCHITECTURE diagram check, ROADMAP update.
- Tag `v0.1.0`.

## v0.2 (depth on connectors and outputs)

- More input sources: Google Drive, Dropbox, Slack, Confluence.
- Service-principal authentication for the database adapter.
- Output channels: dashboard embed (Plotly Dash component), webhook fan-out.
- Menu-driven task chooser in the Electron shell.
- Hillstar host-side adapter (invoke a Testudo container as a Hillstar DAG step).

## v0.3 (depth on sanitisation and validation)

- File-format exploit detection (PDF, Office, archive).
- Schema validation for structured outputs (regression diff against a baseline).
- LLM-as-judge for output quality checks.
- Audit trail visualisation in the Electron shell.

## v0.4 (depth on orchestration)

- Sub-workflows.
- Pause and resume.
- Branching with retry policies.
- DAG editor in the Electron shell.

## Post-v0.4

- Multi-tenancy.
- Distributed execution across hosts.
- Alternative isolation primitives (Firejail, Python-level sandbox) for environments without Docker.
