import { useState } from "react";

type Adapter = "duckdb" | "databricks";

interface Props {
  busy: boolean;
  onRun: (form: {
    adapter: Adapter;
    databasePath: string;
    query: string;
    outputPath: string;
    note: string;
  }) => void;
}

export function DatabasePanel({ busy, onRun }: Props) {
  const [adapter, setAdapter] = useState<Adapter>("duckdb");
  const [databasePath, setDatabasePath] = useState(":memory:");
  const [query, setQuery] = useState("SELECT 1 AS hello");
  const [outputPath, setOutputPath] = useState("/tmp/testudo-db-results.md");
  const [note, setNote] = useState("");

  const submit = () => {
    if (!query.trim()) return;
    onRun({ adapter, databasePath, query: query.trim(), outputPath, note });
  };

  const pickDb = async () => {
    const chosen = await window.testudo.openFile();
    if (chosen) setDatabasePath(chosen);
  };

  return (
    <section className="flex flex-col h-full p-5 gap-4">
      <div>
        <label className="block text-xs uppercase text-muted tracking-wider mb-2">
          Adapter
        </label>
        <div className="inline-flex border border-border rounded overflow-hidden text-sm">
          {(["duckdb", "databricks"] as Adapter[]).map((a) => (
            <button
              key={a}
              type="button"
              onClick={() => setAdapter(a)}
              disabled={a === "databricks"}
              className={`px-4 py-2 ${
                adapter === a
                  ? "bg-accent text-white"
                  : a === "databricks"
                    ? "bg-bg text-muted/40 cursor-not-allowed"
                    : "bg-bg text-muted hover:text-text"
              }`}
            >
              {a === "databricks" ? "Databricks (pending tonight)" : "DuckDB"}
            </button>
          ))}
        </div>
      </div>

      <div>
        <label className="block text-xs uppercase text-muted tracking-wider mb-2">
          {adapter === "duckdb" ? "Database file (or :memory:)" : "Server hostname"}
        </label>
        <div className="flex gap-3">
          <input
            type="text"
            value={databasePath}
            onChange={(e) => setDatabasePath(e.target.value)}
            className="flex-1 bg-bg border border-border rounded px-3 py-2 text-sm focus:outline-none focus:border-accent"
          />
          {adapter === "duckdb" && (
            <button
              type="button"
              onClick={pickDb}
              className="px-3 py-2 rounded bg-bg border border-border hover:border-accent text-sm"
            >
              Pick .duckdb
            </button>
          )}
        </div>
      </div>

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
        disabled={busy || !query.trim() || adapter === "databricks"}
        className="self-end px-5 py-2 rounded bg-accent text-white text-sm font-medium disabled:opacity-40 disabled:cursor-not-allowed"
      >
        {busy ? "Running..." : "Run query"}
      </button>
    </section>
  );
}
