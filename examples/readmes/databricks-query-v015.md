# `databricks-query-v015` -- Databricks SQL → sanitise → markdown

Run a SQL query against a Databricks SQL warehouse, sanitise the
returned rows (PII / cards / secrets / injection markers), write the
redacted rows to disk, and return a chat-inline summary with finding
counts.

## Prerequisites

1. `.env.databricks` filled in (workspace hostname, HTTP path, PAT)
   at the repo root. BridgeManager auto-loads on Start.
2. `databricks-sql-connector` installed:
   `uv pip install -e ".[databricks]"`
3. **Sign-in not required.** PAT is enough; the workspace and warehouse
   must allow your user to query the tables you reference.

## Inputs

| Name | Required | Example | Notes |
|---|---|---|---|
| `query` | yes | `SELECT * FROM samples.bakehouse.sales_transactions LIMIT 10` | Free Edition workspaces ship the `samples.bakehouse` schema (sales_transactions, media_customer_reviews, sales_customers, sales_franchises, sales_suppliers, media_gold_reviews_chunked). |
| `parameters` | no | `[]` (default) | Positional binds for `?` placeholders in the query. Leave `[]` if your query has no `?`. Example: `WHERE customerID = ?` with `parameters: [42]`. |
| `output_path` | yes | `~/testudo/outputs-ui/databricks-result.md` | Where the redacted rows are written. Pre-fills to a sensible default. |

## What the workflow does

```text
query (data.databricks_query)
   │  rows: List[Dict] with columns the query selected
   ▼
sanitise (sanitisers.pii_and_injection, redact=true)
   │  PII / cards / secrets in row values are replaced with
   │  [REDACTED-<label>] markers; injection markers cause reject
   ▼
write_results (outputs.file)
   │  the sanitised rows JSON, written to output_path
   ▼
respond (outputs.chat)
   text: "<critical-count> critical + <high-count> high findings; saved"
   attachments: [output_path]
```

## Three starter queries (click in Workflow tab → Starters)

- **Recent sales transactions** -- smallest smoke test, 10 rows
- **Customer reviews (sanitiser stress)** -- 10 free-text reviews; exercises the PII detector against unstructured English
- **Top 10 customers by purchase count** -- join across two tables

## Common failures

| Error | Cause |
|---|---|
| `ModuleNotFoundError: No module named 'databricks'` | `[databricks]` extra not installed |
| `401 Unauthorized` / `403 Forbidden` | PAT scope or rotation issue. Regenerate as a legacy PAT (no scope picker). |
| `UNRESOLVED_COLUMN.WITH_SUGGESTION` | Column name in the query doesn't exist. The error message lists candidate names. |
| `Connection refused` / DNS error | Wrong hostname in `.env.databricks`, or warehouse is asleep (Serverless cold-start; retry after ~30s) |
