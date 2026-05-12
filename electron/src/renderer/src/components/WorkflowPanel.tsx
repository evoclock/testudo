import { useEffect, useMemo, useState } from "react";
import type { BridgeClient, WorkflowSummary } from "../lib/api";

interface InputSpec {
  type?: string;
  format?: string;
  required?: boolean;
  default?: unknown;
  description?: string;
}

interface Props {
  workflows: WorkflowSummary[];
  busy: boolean;
  client: BridgeClient | null;
  onRun: (workflow: WorkflowSummary, inputs: Record<string, unknown>) => void;
  onSelectionChange?: (workflowName: string) => void;
}

interface Starter {
  label: string;
  hint: string;
  inputs: Record<string, unknown>;
}

/**
 * Per-workflow "starter" presets. Click one and the form gets pre-filled
 * with a known-working combination so the user doesn't have to guess at
 * what query / file / URL / output path to pass.
 */
const STARTERS: Record<string, Starter[]> = {
  "pdf-debrief-v015": [
    {
      label: "sample.md (PII redaction)",
      hint: "Bundled fixture with mock PII; exercises every redaction pattern.",
      inputs: {
        pdf_path: "/home/jgamboa/testudo/examples/data/sample.md",
        output_path: "/home/jgamboa/testudo/outputs-ui/pdf-debrief-sample.md",
      },
    },
  ],
  "pdf-summarise-v015": [
    {
      label: "sample.md → minimax-m2.7:cloud",
      hint: "Bundled fixture summarised by the cloud-served minimax model.",
      inputs: {
        pdf_path: "/home/jgamboa/testudo/examples/data/sample.md",
        model: "minimax-m2.7:cloud",
        output_path: "/home/jgamboa/testudo/outputs-ui/pdf-summarise-sample.md",
      },
    },
    {
      label: "sample.md → mistral (local)",
      hint: "Same fixture, local 7B mistral. Needs `ollama pull mistral` first.",
      inputs: {
        pdf_path: "/home/jgamboa/testudo/examples/data/sample.md",
        model: "mistral:latest",
        output_path: "/home/jgamboa/testudo/outputs-ui/pdf-summarise-mistral.md",
      },
    },
  ],
  "url-fetch-v015": [
    {
      label: "GitHub raw markdown (testudo README)",
      hint: "Fetches a small public markdown over HTTPS.",
      inputs: {
        url: "https://raw.githubusercontent.com/evoclock/testudo/main/README.md",
        output_path: "/home/jgamboa/testudo/outputs-ui/url-fetch-readme.md",
        max_bytes: 10485760,
      },
    },
  ],
  "db-query-v015": [
    {
      label: "DuckDB demo database (meeting M-001 attendees)",
      hint: "Requires examples/data/demo.duckdb (run examples/data/seed_demo.py first).",
      inputs: {
        database_path: "/home/jgamboa/testudo/examples/data/demo.duckdb",
        query: "SELECT name, role FROM attendees WHERE meeting_id = 'M-001'",
        parameters: [],
        output_path: "/home/jgamboa/testudo/outputs-ui/db-query-attendees.md",
      },
    },
  ],
  "databricks-query-v015": [
    {
      label: "10 sales transactions",
      hint: "Smallest smoke test against samples.bakehouse.",
      inputs: {
        query: "SELECT * FROM samples.bakehouse.sales_transactions LIMIT 10",
        parameters: [],
        output_path: "/home/jgamboa/testudo/outputs-ui/databricks-transactions.md",
      },
    },
    {
      label: "10 customer reviews (sanitiser stress)",
      hint: "Free-text reviews; good for exercising the PII / injection sanitiser.",
      inputs: {
        query: "SELECT review_body FROM samples.bakehouse.media_customer_reviews LIMIT 10",
        parameters: [],
        output_path: "/home/jgamboa/testudo/outputs-ui/databricks-reviews.md",
      },
    },
    {
      label: "Top 10 customers by purchase count",
      hint: "Joins sales_transactions with sales_customers; tests multi-table queries.",
      inputs: {
        query:
          "SELECT c.first_name, c.last_name, COUNT(t.transactionID) AS purchases FROM samples.bakehouse.sales_transactions t JOIN samples.bakehouse.sales_customers c ON t.customerID = c.customerID GROUP BY c.first_name, c.last_name ORDER BY purchases DESC LIMIT 10",
        parameters: [],
        output_path: "/home/jgamboa/testudo/outputs-ui/databricks-top-customers.md",
      },
    },
  ],
};

export function WorkflowPanel({ workflows, busy, client, onRun, onSelectionChange }: Props) {
  const [selectedName, setSelectedName] = useState<string>("");
  const [form, setForm] = useState<Record<string, unknown>>({});
  // Separate text-buffer for array inputs so typing does not round-trip
  // through JSON.stringify/parse on every keystroke (which previously
  // turned each `"` typed into cascading "\\\\\\\"" escapes).
  const [arrayBuffers, setArrayBuffers] = useState<Record<string, string>>({});
  const [arrayErrors, setArrayErrors] = useState<Record<string, string | null>>({});
  const [readme, setReadme] = useState<string | null>(null);
  const [readmeOpen, setReadmeOpen] = useState(false);

  const selected = useMemo(
    () => workflows.find((w) => w.name === selectedName) ?? null,
    [workflows, selectedName],
  );

  const starters = useMemo<Starter[]>(
    () => (selected ? (STARTERS[selected.name] ?? []) : []),
    [selected],
  );

  useEffect(() => {
    onSelectionChange?.(selectedName);
  }, [selectedName, onSelectionChange]);

  useEffect(() => {
    let cancelled = false;
    if (!selected || !client) {
      setReadme(null);
      return;
    }
    void (async () => {
      try {
        const md = await client.workflowReadme(selected.name);
        if (!cancelled) setReadme(md);
      } catch {
        if (!cancelled) setReadme(null);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [selected, client]);

  useEffect(() => {
    if (!selected) {
      setForm({});
      return;
    }
    const seed: Record<string, unknown> = {};
    for (const [key, raw] of Object.entries(selected.inputs)) {
      const spec = raw as InputSpec;
      if (spec.default !== undefined) {
        seed[key] = spec.default;
      } else if (spec.type === "file" && key.includes("output")) {
        seed[key] = `/home/jgamboa/testudo/outputs-ui/testudo-${selected.name}.md`;
      } else if (spec.type === "array") {
        seed[key] = [];
      }
    }
    setForm(seed);
  }, [selected]);

  const placeholderFor = (key: string, spec: InputSpec): string => {
    if (spec.default !== undefined) return `default: ${JSON.stringify(spec.default).slice(0, 60)}`;
    if (spec.type === "array") return "[]";
    if (spec.type === "integer" || spec.type === "number") return "0";
    if (key === "query") return "SELECT * FROM samples.bakehouse.sales_transactions LIMIT 10";
    if (key === "url") return "https://example.com/file.md";
    if (key.includes("path")) return "/home/jgamboa/testudo/outputs-ui/testudo-output.md";
    return spec.required ? "(required)" : "(optional)";
  };

  const updateField = (key: string, value: unknown) => {
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  const pickFor = async (key: string) => {
    const chosen = await window.testudo.openFile();
    if (chosen) updateField(key, chosen);
  };

  const applyStarter = (starter: Starter) => {
    setForm((prev) => ({ ...prev, ...starter.inputs }));
  };

  const missingRequired = useMemo(() => {
    if (!selected) return [];
    return Object.entries(selected.inputs)
      .filter(([key, raw]) => {
        const spec = raw as InputSpec;
        if (!spec.required) return false;
        const v = form[key];
        return v === undefined || v === null || v === "";
      })
      .map(([key]) => key);
  }, [selected, form]);

  const submit = () => {
    if (!selected || missingRequired.length > 0) return;
    onRun(selected, form);
  };

  return (
    <section className="flex flex-col h-full p-5 gap-4">
      <div>
        <label className="block text-xs uppercase text-muted tracking-wider mb-2">
          Workflow
        </label>
        <select
          value={selectedName}
          onChange={(e) => setSelectedName(e.target.value)}
          className="w-full bg-bg border border-border rounded px-3 py-2 text-sm focus:outline-none focus:border-accent"
        >
          <option value="">-- pick a workflow --</option>
          {workflows.map((wf) => (
            <option key={wf.path} value={wf.name}>
              {wf.name} ({wf.step_count} steps)
            </option>
          ))}
        </select>
        {selected?.description && (
          <p className="text-xs text-muted mt-2">{selected.description}</p>
        )}
        {readme && (
          <details
            open={readmeOpen}
            onToggle={(e) => setReadmeOpen((e.target as HTMLDetailsElement).open)}
            className="mt-2"
          >
            <summary className="cursor-pointer text-xs text-accent hover:underline">
              {readmeOpen ? "Hide README" : "Show README (usage, inputs, common failures)"}
            </summary>
            <pre className="mt-2 text-xs bg-bg border border-border rounded p-3 whitespace-pre-wrap font-mono max-h-96 overflow-y-auto">
              {readme}
            </pre>
          </details>
        )}
      </div>

      {selected && starters.length > 0 && (
        <div>
          <label className="block text-xs uppercase text-muted tracking-wider mb-2">
            Starter examples (click to pre-fill)
          </label>
          <div className="grid grid-cols-1 gap-2">
            {starters.map((s) => (
              <button
                key={s.label}
                type="button"
                onClick={() => applyStarter(s)}
                className="text-left px-3 py-2 rounded bg-bg border border-border hover:border-accent text-sm"
                title={Object.entries(s.inputs)
                  .map(([k, v]) => `${k}=${JSON.stringify(v).slice(0, 80)}`)
                  .join("\n")}
              >
                <div className="text-text">{s.label}</div>
                <div className="text-xs text-muted">{s.hint}</div>
              </button>
            ))}
          </div>
        </div>
      )}

      {selected && (
        <div className="flex-1 overflow-y-auto space-y-3">
          {Object.entries(selected.inputs).map(([key, raw]) => {
            const spec = raw as InputSpec;
            const isFile = spec.type === "file";
            const isArray = spec.type === "array";
            const isNumber = spec.type === "integer" || spec.type === "number";
            const v = form[key];

            return (
              <div key={key}>
                <label className="block text-xs uppercase text-muted tracking-wider mb-1">
                  {key}
                  {spec.required && <span className="text-red-400 ml-1">*</span>}
                  {spec.format && (
                    <span className="text-muted/60 ml-2 normal-case">
                      ({spec.format})
                    </span>
                  )}
                </label>
                {spec.description && (
                  <p className="text-xs text-muted mb-1">{spec.description}</p>
                )}
                {isArray && arrayErrors[key] && (
                  <p className="text-xs text-amber-400 mb-1">{arrayErrors[key]}</p>
                )}
                <div className="flex gap-2">
                  {isArray ? (
                    <input
                      type="text"
                      value={
                        arrayBuffers[key] !== undefined
                          ? arrayBuffers[key]
                          : JSON.stringify(v ?? [])
                      }
                      onChange={(e) => {
                        setArrayBuffers((b) => ({ ...b, [key]: e.target.value }));
                      }}
                      onBlur={(e) => {
                        const text = e.target.value.trim();
                        if (text === "") {
                          updateField(key, []);
                          setArrayBuffers((b) => {
                            const next = { ...b };
                            delete next[key];
                            return next;
                          });
                          setArrayErrors((er) => ({ ...er, [key]: null }));
                          return;
                        }
                        try {
                          const parsed = JSON.parse(text);
                          if (!Array.isArray(parsed)) {
                            setArrayErrors((er) => ({
                              ...er,
                              [key]: "must be a JSON array, e.g. [] or [\"a\", 1]",
                            }));
                            return;
                          }
                          updateField(key, parsed);
                          setArrayBuffers((b) => {
                            const next = { ...b };
                            delete next[key];
                            return next;
                          });
                          setArrayErrors((er) => ({ ...er, [key]: null }));
                        } catch (err) {
                          setArrayErrors((er) => ({
                            ...er,
                            [key]: `invalid JSON: ${(err as Error).message}`,
                          }));
                        }
                      }}
                      placeholder="[]  or  [&quot;value&quot;, 42, true]"
                      className="flex-1 bg-bg border border-border rounded px-3 py-2 text-sm font-mono focus:outline-none focus:border-accent"
                    />
                  ) : (
                    <input
                      type={isNumber ? "number" : "text"}
                      value={v == null ? "" : String(v)}
                      onChange={(e) => {
                        if (isNumber) {
                          updateField(key, Number(e.target.value));
                        } else {
                          updateField(key, e.target.value);
                        }
                      }}
                      placeholder={placeholderFor(key, spec)}
                      className="flex-1 bg-bg border border-border rounded px-3 py-2 text-sm focus:outline-none focus:border-accent"
                    />
                  )}
                  {isFile && (
                    <button
                      type="button"
                      onClick={() => pickFor(key)}
                      className="px-3 py-2 rounded bg-bg border border-border hover:border-accent text-sm"
                    >
                      Pick
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      <div className="flex items-center justify-end gap-3">
        {missingRequired.length > 0 && (
          <span className="text-xs text-muted">
            Missing: {missingRequired.join(", ")}
          </span>
        )}
        <button
          type="button"
          onClick={submit}
          disabled={busy || !selected || missingRequired.length > 0}
          className="px-5 py-2 rounded bg-accent text-white text-sm font-medium disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {busy ? "Running..." : "Run workflow"}
        </button>
      </div>
    </section>
  );
}
