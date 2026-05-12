import { useState } from "react";

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

export function DatabasePanel({ busy, databricksReady, onRun }: Props) {
  const [adapter, setAdapter] = useState<Adapter>("duckdb");
  const [databasePath, setDatabasePath] = useState(":memory:");
  const [query, setQuery] = useState(DUCKDB_QUERY_DEFAULT);
  const [outputPath, setOutputPath] = useState("/tmp/testudo-db-results.md");
  const [note, setNote] = useState("");

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
        <div>
          <label className="block text-xs uppercase text-muted tracking-wider mb-2">
            Database file (or :memory:)
          </label>
          <div className="flex gap-3">
            <input
              type="text"
              value={databasePath}
              onChange={(e) => setDatabasePath(e.target.value)}
              className="flex-1 bg-bg border border-border rounded px-3 py-2 text-sm focus:outline-none focus:border-accent"
            />
            <button
              type="button"
              onClick={pickDb}
              className="px-3 py-2 rounded bg-bg border border-border hover:border-accent text-sm"
            >
              Pick .duckdb
            </button>
          </div>
        </div>
      )}

      {adapter === "databricks" && (
        <div>
          <label className="block text-xs uppercase text-muted tracking-wider mb-2">
            Connection
          </label>
          <p className="text-xs text-muted">
            Reads <code className="text-text">DATABRICKS_SERVER_HOSTNAME</code> /{" "}
            <code className="text-text">HTTP_PATH</code> /{" "}
            <code className="text-text">TOKEN</code> from the bridge process env.
            Free Edition ships{" "}
            <code className="text-text">samples.bakehouse</code> (sales_transactions,
            media_customer_reviews, sales_customers, sales_franchises,
            sales_suppliers, media_gold_reviews_chunked).
          </p>
        </div>
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
