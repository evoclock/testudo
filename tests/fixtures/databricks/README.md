# Databricks test fixtures

Sample dataset + table DDL + bundled workflow you can use to verify
the `data.databricks_query` adapter once your workspace is provisioned.

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

### 5. Run the bundled workflow

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

## Privacy note

`sample_employees.csv` and `sample_transactions.csv` are mock-PII
generators tuned to trigger every UK + several international regex
patterns in the sanitiser. None of the names, emails, IBANs, or card
numbers belong to real people, accounts, or cards. Safe to upload to a
private Databricks workspace under your own ownership.
