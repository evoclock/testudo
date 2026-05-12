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

Drop a `workflow.json` plus inputs into a Testudo container. The embedded lightweight orchestrator runs the workflow to completion. The container handles isolation, permissioning, audit, and rollback. Outputs come back to the host plus a full audit trail.

### 2. Testudo as a Hillstar DAG step

Larger pipelines run on [Hillstar](https://github.com/evoclock/hillstar-orchestrator). When a step needs hardened isolation (untrusted input, sensitive credentials, third-party tool execution), Hillstar invokes a Testudo container via a host-side adapter. The same `Tool` and `Workflow` interfaces work in both, so a tool written for Hillstar runs unchanged inside Testudo.

## What Testudo is NOT

- A multi-provider LLM library. Testudo containers either (a) call out to Hillstar for provider routing, or (b) bind one specific provider at image build time.
- An MCP server host. Hillstar already hosts MCP servers.
- A DAG visualiser. Hillstar generates Mermaid diagrams.
- A multi-tenant orchestrator. One runtime per machine in v0.x.
- A general-purpose sandbox. Testudo is shaped for *agent* execution: tool-call patterns, structured workflow steps, audit trails. A general-purpose Linux sandbox is a different product.

## Internal layers (v0.1)

```text
+-------------------------------------------------------+
| Electron UI (host-side, optional)                     |
|   chat box | file upload | output panel               |
+-----------------------+-------------------------------+
                        |
                        v
+-------------------------------------------------------+
| testudo CLI (host-side)                               |
|   docker run testudo:0.1 ...                          |
+-----------------------+-------------------------------+
                        |
                        v
+=======================================================+
| Testudo container                                     |
| +---------------------------------------------------+ |
| | runtime/         Docker namespace; cgroup limits  | |
| | permissions/     declarative model; enforcement    | |
| | audit/           JSONL writer per invocation       | |
| | orchestrator/    workflow.json runner             | |
| | connectors/      file ingest (HTTPS, local)       | |
| | sanitisers/      PII + injection-pattern checks    | |
| | data/            DuckDB default; Databricks opt   | |
| | outputs/         file + chat-inline               | |
| +---------------------------------------------------+ |
+=======================================================+
                        |
                        v
+-------------------------------------------------------+
| Outputs delivered back to host                        |
|   audit log (JSONL) | result file | chat response     |
+-------------------------------------------------------+
```

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
