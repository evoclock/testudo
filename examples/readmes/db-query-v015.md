# `db-query-v015` -- DuckDB query → write

Run a parameterised SQL query against a DuckDB database file (or
`:memory:`), write the result rows to disk as JSON.

## Prerequisites

- DuckDB is bundled (default dependency of testudo). No extras needed.
- A `.duckdb` file you can read. The bundled demo at
  `examples/data/demo.duckdb` is built by running
  `python examples/data/seed_demo.py` once.

## Inputs

| Name | Required | Example | Notes |
|---|---|---|---|
| `database_path` | yes | `/home/jgamboa/testudo/examples/data/demo.duckdb` or `:memory:` | Path to the DuckDB file. `:memory:` runs a transient session. |
| `query` | yes | `SELECT name, role FROM attendees WHERE meeting_id = 'M-001'` | Standard SQL. |
| `parameters` | no | `[]` (default) | Positional binds for `?` placeholders. |
| `output_path` | yes | `/home/jgamboa/testudo/outputs-ui/db-query-result.md` | Where the rows JSON is written. |

## Starter (click in Workflow tab → Starters)

- **DuckDB demo database (meeting M-001 attendees)** -- pre-seeds the
  query against the bundled demo db. Requires `seed_demo.py` ran first.

## What the workflow does

```text
query (data.duckdb_query)
   │  rows: List[Dict]
   ▼
write_results (outputs.file)
   │  JSON-encoded rows
   ▼
respond (outputs.chat)
```

## Note on PII

This workflow does NOT include a sanitiser step (DuckDB queries on
your own local data are typically already trusted). If your DuckDB
contents include PII, swap in `sanitisers.pii_and_injection` or use
the `databricks-query-v015` workflow as a template (it has the
sanitiser step wired).
