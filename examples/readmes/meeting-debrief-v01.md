# `meeting-debrief-v01` -- Transcript + DuckDB lookup demo

The original v0.1 vertical-slice demo. Reads a meeting transcript
from disk, sanitises, looks up attendee metadata in the bundled
DuckDB demo, writes a debrief markdown, and returns a chat-inline
response.

## Prerequisites

1. Seed the demo DuckDB once:
   ```bash
   python examples/data/seed_demo.py
   ```
2. The sample transcript at `examples/data/transcript.md` is bundled
   in the repo.

## Inputs

| Name | Required | Example | Notes |
|---|---|---|---|
| `transcript_path` | yes | `examples/data/transcript.md` | Markdown / text meeting transcript. |
| `demo_db_path` | yes | `examples/data/demo.duckdb` | Path to the seeded DuckDB. |
| `meeting_id` | no | `M-001` (default) | Filters the attendees table. |
| `output_path` | yes | `runs/debrief.md` | Where the debrief is written. |

## What the workflow does

```text
ingest (connectors.local_file)
   ▼
sanitise (sanitisers.pii_and_injection)
   ▼
lookup_attendees (data.duckdb_query) -- runs in parallel with sanitise
   ▼
write_debrief (outputs.file)
   ▼
respond (outputs.chat)
```

## When to use

This is the canonical "everything wired together" example. Use it as
a template when you want to compose:
- file ingestion +
- sanitisation +
- structured database lookup +
- file output +
- chat response.

Newer workflows (`pdf-summarise`, `databricks-query`) inherit the
same step shapes.
