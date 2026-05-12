# Databricks test fixtures

Sample dataset + table DDL + bundled workflow you can use to verify
the `data.databricks_query` adapter once your workspace is provisioned.

## Fastest path: use the built-in `samples.bakehouse` schema

Databricks Free Edition ships a `samples` catalog with the `bakehouse`
demo schema pre-populated. Skip the CSV upload entirely if you just
want to verify the adapter wiring; query one of these instead:

| Table | Shape | Best for |
|---|---|---|
| `samples.bakehouse.sales_transactions` | Structured rows: transaction_id, customer_id, total_amount, transaction_date | Wiring smoke-test (clean structured data) |
| `samples.bakehouse.sales_customers` | Customer rows: customer_id, name, email, phone, address | Sanitiser smoke-test (real-shape PII columns) |
| `samples.bakehouse.media_customer_reviews` | Free-text review_body column | Best sanitiser test (free text can hit PII / injection patterns) |
| `samples.bakehouse.media_gold_reviews_chunked` | Pre-chunked review text | RAG-style retrieval against the same data |
| `samples.bakehouse.sales_suppliers` | Supplier rows | Joins with sales_transactions |
| `samples.bakehouse.sales_franchises` | Franchise rows | Joins with sales_transactions |

### Quick smoke tests

```bash
# 1. Wiring check -- 10 transaction rows
testudo run tests/fixtures/databricks/sample_workflow_databricks.json \
  --inputs-json <(echo '{
    "query": "SELECT * FROM samples.bakehouse.sales_transactions LIMIT 10",
    "output_path": "runs/bakehouse-transactions.md"
  }')

# 2. Sanitiser exercise -- 10 reviews with free text
testudo run tests/fixtures/databricks/sample_workflow_databricks.json \
  --inputs-json <(echo '{
    "query": "SELECT review_body FROM samples.bakehouse.media_customer_reviews LIMIT 10",
    "output_path": "runs/bakehouse-reviews.md"
  }')

# 3. Join across schemas
testudo run tests/fixtures/databricks/sample_workflow_databricks.json \
  --inputs-json <(echo '{
    "query": "SELECT c.name, COUNT(t.transaction_id) AS purchases FROM samples.bakehouse.sales_transactions t JOIN samples.bakehouse.sales_customers c ON t.customer_id = c.customer_id GROUP BY c.name ORDER BY purchases DESC LIMIT 10",
    "output_path": "runs/bakehouse-top-customers.md"
  }')
```

A **Serverless Starter Warehouse** comes pre-configured on Free
Edition; the connection details are on its Connection Details tab.
Use those for the env vars below.

Move to the upload-your-own-data path further down only if you want
the sanitiser exercise against rows that hit testudo's specific UK /
international PII regex patterns (e.g. UK postcode, NIN). The
bakehouse data contains realistic shapes but not the exact formats
testudo's UK patterns key on.

## Upload-your-own path (for PII sanitiser testing)

The fixtures bundled here are mock-PII tuned to trigger the
sanitiser's regex patterns. Use this path when you want to confirm
end-to-end behaviour with realistic PII shapes.

## What's in here

| File | Purpose |
|---|---|
| `sample_employees.csv` | 50 mock employee rows: id, name, email, phone, postcode, department, salary, hire_date. PII fields are crafted to match testudo's UK regex patterns. |
| `sample_transactions.csv` | 50 mock transactions: id, amount, iban, card, timestamp, status. PCI-style fields for sanitiser stress. |
| `create_tables.sql` | DDL to create the two tables, ready to paste into a Databricks SQL editor. |
| `sample_workflow_databricks.json` | Bundled workflow: query → sanitise → write → respond. Uses `data.databricks_query`; requires the `[databricks]` extra installed. |

## Step-by-step setup

### 1. Install the optional dependency

```bash
uv pip install -e ".[databricks]"
```

That pulls in `databricks-sql-connector`. The testudo runtime stays
slim by default; the adapter is opt-in via this extra.

### 2. Get your workspace details

From the Databricks workspace UI:

- **Server hostname** -- e.g. `dbc-abc1234d-5678.cloud.databricks.com`.
  Workspace -> SQL Warehouses -> pick a warehouse -> Connection details.
- **HTTP path** -- on the same Connection details page, e.g.
  `/sql/1.0/warehouses/abc123def456`.
- **Personal access token** -- User settings -> Developer -> Access
  tokens -> Generate new token. Copy it once; you cannot see it again.

Export them:

```bash
export DATABRICKS_SERVER_HOSTNAME="dbc-abc1234d-5678.cloud.databricks.com"
export DATABRICKS_HTTP_PATH="/sql/1.0/warehouses/abc123def456"
export DATABRICKS_TOKEN="dapi..."   # the token you generated
```

### 3. Upload the sample data

There are two paths depending on your Databricks tier:

#### Path A: Catalog + Volume (Unity Catalog, current best practice)

```text
1. In the Databricks UI, navigate to Catalog -> Volumes.
2. Pick or create a schema (e.g. main.default).
3. Click "Create Volume" -> "Managed Volume" -> name it "testudo_fixtures".
4. Open the volume, click "Upload to this volume", and drop in
   sample_employees.csv and sample_transactions.csv.
```

#### Path B: DBFS (legacy, still works)

```text
1. Workspace UI -> Data -> Upload File.
2. Choose Upload Data and drag both CSVs in.
3. Take the DBFS path Databricks shows you for each upload, e.g.
   /FileStore/tables/sample_employees.csv.
```

### 4. Create the tables

Open a SQL editor in Databricks. Paste the contents of
`create_tables.sql`, then **edit the two `LOCATION` lines** so they
point at the paths you uploaded in step 3 (Volume path or DBFS path).
Run the script.

Verify:

```sql
SELECT count(*) FROM testudo.employees;   -- 50
SELECT count(*) FROM testudo.transactions; -- 50
```

### 5. Run the bundled workflow (mock-PII path)

```bash
testudo run tests/fixtures/databricks/sample_workflow_databricks.json \
  --inputs-json <(echo '{
    "query": "SELECT name, email, department FROM testudo.employees LIMIT 10",
    "output_path": "runs/databricks-debrief.md"
  }')
```

Or from the Electron UI: Database tab -> Adapter "Databricks" -> paste
the same query -> Run. (The UI surfaces Databricks once the env vars
are exported; the toggle is currently disabled with a "pending tonight"
hint.)

## Permissions that actually matter

The PAT authenticates you, but Databricks still enforces table-level
permissions on top. For the `samples` catalog path nothing needs to be
granted -- it's readable by every workspace user by default. For your
own catalogs you'll need:

- **CAN USE** on the SQL Warehouse (Workspace UI -> SQL Warehouses ->
  your warehouse -> Permissions).
- **USE CATALOG / USE SCHEMA / SELECT** on the tables (Unity Catalog
  UI -> your catalog -> your schema -> Permissions).

Without those, the query fails with a clear "user does not have
permission" message.

## Privacy note

`sample_employees.csv` and `sample_transactions.csv` are mock-PII
generators tuned to trigger every UK + several international regex
patterns in the sanitiser. None of the names, emails, IBANs, or card
numbers belong to real people, accounts, or cards. Safe to upload to a
private Databricks workspace under your own ownership.
