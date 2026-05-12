import { useEffect, useState } from "react";

export type Adapter = "duckdb" | "databricks";

interface Props {
  busy: boolean;
  databricksReady: boolean;
  onRun: (form: {
    adapter: Adapter;
    databasePath: string;
    query: string;
    outputPath: string;
    note: string;
  }) => void;
}

const DUCKDB_QUERY_DEFAULT = "SELECT 1 AS hello";
const DATABRICKS_QUERY_DEFAULT =
  "SELECT * FROM samples.bakehouse.sales_transactions LIMIT 10";

const DEMO_DUCKDB_PATH = "/home/jgamboa/testudo/examples/data/demo.duckdb";

const DUCKDB_SAMPLE_QUERIES: Array<{ label: string; sql: string; database?: string }> = [
  {
    label: "Demo db: M-001 attendees (3 rows)",
    sql: "SELECT name, role FROM attendees WHERE meeting_id = 'M-001'",
    database: DEMO_DUCKDB_PATH,
  },
  {
    label: "Demo db: M-002 attendees (2 rows)",
    sql: "SELECT name, role FROM attendees WHERE meeting_id = 'M-002'",
    database: DEMO_DUCKDB_PATH,
  },
  {
    label: "Demo db: all attendees grouped by meeting",
    sql: "SELECT meeting_id, COUNT(*) AS attendees FROM attendees GROUP BY meeting_id ORDER BY meeting_id",
    database: DEMO_DUCKDB_PATH,
  },
  {
    label: "In-memory: literal smoke test",
    sql: "SELECT 1 AS hello, 'world' AS greeting",
    database: ":memory:",
  },
];

const DATABRICKS_SAMPLE_QUERIES: Array<{ label: string; sql: string }> = [
  {
    label: "Recent sales transactions",
    sql: "SELECT * FROM samples.bakehouse.sales_transactions LIMIT 10",
  },
  {
    label: "Free-text customer reviews (sanitiser exercise)",
    sql: "SELECT review, review_date FROM samples.bakehouse.media_customer_reviews LIMIT 10",
  },
  {
    label: "Customer purchase counts",
    sql: "SELECT c.first_name, c.last_name, COUNT(t.transactionID) AS purchases FROM samples.bakehouse.sales_transactions t JOIN samples.bakehouse.sales_customers c ON t.customerID = c.customerID GROUP BY c.first_name, c.last_name ORDER BY purchases DESC LIMIT 10",
  },
  {
    label: "Suppliers",
    sql: "SELECT * FROM samples.bakehouse.sales_suppliers LIMIT 20",
  },
  {
    label: "Franchises",
    sql: "SELECT * FROM samples.bakehouse.sales_franchises LIMIT 20",
  },
];

export function DatabasePanel({ busy, databricksReady, onRun }: Props) {
  const [adapter, setAdapter] = useState<Adapter>(
    databricksReady ? "databricks" : "duckdb",
  );
  const [databasePath, setDatabasePath] = useState(
    databricksReady ? "" : ":memory:",
  );
  const [query, setQuery] = useState(
    databricksReady ? DATABRICKS_QUERY_DEFAULT : DUCKDB_QUERY_DEFAULT,
  );
  const [outputPath, setOutputPath] = useState(
    "/home/jgamboa/testudo/outputs-ui/testudo-db-results.md",
  );
  const [note, setNote] = useState("");

  // If env-check arrives after mount and reports Databricks ready, flip the
  // default adapter so the user lands on the path they actually configured.
  useEffect(() => {
    if (databricksReady && adapter === "duckdb" && query === DUCKDB_QUERY_DEFAULT) {
      setAdapter("databricks");
      setQuery(DATABRICKS_QUERY_DEFAULT);
      setDatabasePath("");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [databricksReady]);

  const switchAdapter = (next: Adapter) => {
    setAdapter(next);
    if (next === "databricks") {
      setQuery((q) => (q === DUCKDB_QUERY_DEFAULT ? DATABRICKS_QUERY_DEFAULT : q));
      setDatabasePath("");
    } else {
      setQuery((q) => (q === DATABRICKS_QUERY_DEFAULT ? DUCKDB_QUERY_DEFAULT : q));
      setDatabasePath(":memory:");
    }
  };

  const submit = () => {
    if (!query.trim()) return;
    onRun({ adapter, databasePath, query: query.trim(), outputPath, note });
  };

  const pickDb = async () => {
    const chosen = await window.testudo.openFile();
    if (chosen) setDatabasePath(chosen);
  };

  const databricksDisabled = !databricksReady;

  return (
    <section className="flex flex-col h-full p-5 gap-4">
      <div>
        <label className="block text-xs uppercase text-muted tracking-wider mb-2">
          Adapter
        </label>
        <div className="inline-flex border border-border rounded overflow-hidden text-sm">
          <button
            type="button"
            onClick={() => switchAdapter("duckdb")}
            className={`px-4 py-2 ${
              adapter === "duckdb"
                ? "bg-accent text-white"
                : "bg-bg text-muted hover:text-text"
            }`}
          >
            DuckDB
          </button>
          <button
            type="button"
            onClick={() => switchAdapter("databricks")}
            disabled={databricksDisabled}
            title={
              databricksDisabled
                ? "DATABRICKS_SERVER_HOSTNAME / HTTP_PATH / TOKEN not exported in the bridge process env. Source .env.databricks before starting the bridge."
                : "Databricks env vars detected"
            }
            className={`px-4 py-2 ${
              adapter === "databricks"
                ? "bg-accent text-white"
                : databricksDisabled
                  ? "bg-bg text-muted/40 cursor-not-allowed"
                  : "bg-bg text-muted hover:text-text"
            }`}
          >
            {databricksDisabled ? "Databricks (env not set)" : "Databricks"}
          </button>
        </div>
      </div>

      {adapter === "duckdb" && (
        <>
          <div>
            <label className="block text-xs uppercase text-muted tracking-wider mb-2">
              Starter queries
            </label>
            <div className="grid grid-cols-1 gap-2">
              {DUCKDB_SAMPLE_QUERIES.map((q) => (
                <button
                  key={q.label}
                  type="button"
                  onClick={() => {
                    setQuery(q.sql);
                    if (q.database) setDatabasePath(q.database);
                  }}
                  className="text-left px-3 py-2 rounded bg-bg border border-border hover:border-accent text-xs"
                  title={q.sql}
                >
                  <div className="text-text">{q.label}</div>
                  <div className="text-[10px] text-muted font-mono truncate">{q.sql}</div>
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-xs uppercase text-muted tracking-wider mb-2">
              Database file (or :memory:)
            </label>
            <div className="flex gap-3 items-center">
              <input
                type="text"
                value={databasePath}
                onChange={(e) => setDatabasePath(e.target.value)}
                className="flex-1 bg-bg border border-border rounded px-3 py-2 text-sm focus:outline-none focus:border-accent"
              />
              <button
                type="button"
                onClick={() => setDatabasePath(DEMO_DUCKDB_PATH)}
                className="px-3 py-2 rounded bg-bg border border-border hover:border-accent text-sm whitespace-nowrap"
                title={`Set path to the bundled demo db at ${DEMO_DUCKDB_PATH}`}
              >
                Use demo db
              </button>
              <button
                type="button"
                onClick={pickDb}
                className="px-3 py-2 rounded bg-bg border border-border hover:border-accent text-sm whitespace-nowrap"
              >
                Pick .duckdb
              </button>
            </div>
            <p className="text-[11px] text-muted mt-2">
              <code className="text-text">:memory:</code> runs a transient session
              (good for SELECT-literal smoke tests). Or point at a .duckdb file.
              The bundled demo db at{" "}
              <code className="text-text">{DEMO_DUCKDB_PATH}</code> has one
              table: <code className="text-text">attendees(meeting_id, name, role)</code>{" "}
              with 5 rows across <code className="text-text">M-001</code> /{" "}
              <code className="text-text">M-002</code>. Regenerate with{" "}
              <code className="text-text">
                python examples/data/seed_demo.py
              </code>
              .
            </p>
          </div>
        </>
      )}

      {adapter === "databricks" && (
        <>
          <div>
            <label className="block text-xs uppercase text-muted tracking-wider mb-2">
              Sample queries
            </label>
            <div className="grid grid-cols-2 gap-2">
              {DATABRICKS_SAMPLE_QUERIES.map((q) => (
                <button
                  key={q.label}
                  type="button"
                  onClick={() => setQuery(q.sql)}
                  className="text-left px-3 py-2 rounded bg-bg border border-border hover:border-accent text-xs"
                  title={q.sql}
                >
                  <div className="text-text">{q.label}</div>
                  <div className="text-[10px] text-muted font-mono truncate">
                    {q.sql}
                  </div>
                </button>
              ))}
            </div>
            <p className="text-[11px] text-muted mt-2">
              Reads{" "}
              <code className="text-text">DATABRICKS_SERVER_HOSTNAME</code> /{" "}
              <code className="text-text">HTTP_PATH</code> /{" "}
              <code className="text-text">TOKEN</code> from the bridge process env.
              Free Edition ships <code className="text-text">samples.bakehouse</code>.
            </p>
          </div>
        </>
      )}

      <div className="flex-1 flex flex-col">
        <label className="block text-xs uppercase text-muted tracking-wider mb-2">
          SQL query
        </label>
        <textarea
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          rows={6}
          className="flex-1 w-full bg-bg border border-border rounded p-3 text-sm font-mono resize-none focus:outline-none focus:border-accent"
        />
      </div>

      <div>
        <label className="block text-xs uppercase text-muted tracking-wider mb-2">
          Output path
        </label>
        <input
          type="text"
          value={outputPath}
          onChange={(e) => setOutputPath(e.target.value)}
          className="w-full bg-bg border border-border rounded px-3 py-2 text-sm focus:outline-none focus:border-accent"
        />
      </div>

      <div>
        <label className="block text-xs uppercase text-muted tracking-wider mb-2">
          Note (context for the chat log)
        </label>
        <textarea
          value={note}
          onChange={(e) => setNote(e.target.value)}
          rows={2}
          placeholder="Optional"
          className="w-full bg-bg border border-border rounded p-3 text-sm resize-none focus:outline-none focus:border-accent"
        />
      </div>

      <button
        type="button"
        onClick={submit}
        disabled={busy || !query.trim()}
        className="self-end px-5 py-2 rounded bg-accent text-white text-sm font-medium disabled:opacity-40 disabled:cursor-not-allowed"
      >
        {busy ? "Running..." : "Run query"}
      </button>
    </section>
  );
}
