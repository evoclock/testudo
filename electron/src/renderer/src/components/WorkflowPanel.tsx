import { useEffect, useMemo, useState } from "react";
import Markdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import type { BridgeClient, WorkflowSummary } from "../lib/api";

const MD_REMARK_PLUGINS = [remarkGfm];

const MD_COMPONENTS: Components = {
  h1: (props) => (
    <h1
      className="text-lg font-semibold text-text mt-1 mb-3 pb-1 border-b border-border"
      {...props}
    />
  ),
  h2: (props) => (
    <h2 className="text-base font-semibold text-text mt-4 mb-2" {...props} />
  ),
  h3: (props) => (
    <h3 className="text-sm font-semibold text-text mt-3 mb-1" {...props} />
  ),
  h4: (props) => (
    <h4
      className="text-xs font-semibold uppercase tracking-wider text-muted mt-2 mb-1"
      {...props}
    />
  ),
  p: (props) => <p className="text-xs leading-relaxed mb-2 text-text/90" {...props} />,
  ul: (props) => (
    <ul className="list-disc ml-5 mb-2 text-xs space-y-0.5 text-text/90" {...props} />
  ),
  ol: (props) => (
    <ol className="list-decimal ml-5 mb-2 text-xs space-y-0.5 text-text/90" {...props} />
  ),
  li: (props) => <li className="leading-relaxed" {...props} />,
  code: (props) => (
    <code
      className="bg-panel px-1 rounded font-mono text-[0.9em] break-words"
      {...props}
    />
  ),
  pre: (props) => (
    <pre
      className="bg-panel border border-border rounded p-2 text-[11px] overflow-x-auto mb-2 [&_code]:bg-transparent [&_code]:border-0 [&_code]:p-0 [&_code]:text-inherit"
      {...props}
    />
  ),
  a: (props) => (
    <a className="text-accent underline" target="_blank" rel="noreferrer" {...props} />
  ),
  strong: (props) => <strong className="font-semibold text-text" {...props} />,
  em: (props) => <em className="italic" {...props} />,
  blockquote: (props) => (
    <blockquote
      className="border-l-2 border-border pl-3 text-muted italic mb-2 text-xs"
      {...props}
    />
  ),
  hr: () => <hr className="my-3 border-border" />,
  table: (props) => (
    <div className="overflow-x-auto -mx-1 mb-2">
      <table className="border-collapse text-xs w-full" {...props} />
    </div>
  ),
  thead: (props) => <thead className="bg-panel" {...props} />,
  th: (props) => (
    <th className="border border-border px-2 py-1 text-left font-semibold text-text" {...props} />
  ),
  td: (props) => (
    <td className="border border-border px-2 py-1 align-top text-text/90" {...props} />
  ),
};

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
  onRun: (
    workflow: WorkflowSummary,
    inputs: Record<string, unknown>,
    note?: string,
  ) => void;
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
      label: "Hillstar-orchestrator README (public GitHub raw)",
      hint: "Fetches a small public markdown over HTTPS.",
      inputs: {
        url: "https://raw.githubusercontent.com/evoclock/hillstar-orchestrator/main/README.md",
        output_path: "/home/jgamboa/testudo/outputs-ui/url-fetch-hillstar-readme.md",
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
        query: "SELECT review, review_date FROM samples.bakehouse.media_customer_reviews LIMIT 10",
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
  const [note, setNote] = useState("");

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
    onRun(selected, form, note.trim() || undefined);
  };

  return (
    <section className="flex flex-col h-full p-5 gap-4">
      <div>
        <label className="block text-[11px] uppercase tracking-[0.12em] text-muted2 font-semibold mb-2">
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
            <div className="mt-2 bg-bg border border-border rounded p-3 max-h-96 overflow-y-auto">
              <Markdown remarkPlugins={MD_REMARK_PLUGINS} components={MD_COMPONENTS}>
                {readme}
              </Markdown>
            </div>
          </details>
        )}
      </div>

      {selected && starters.length > 0 && (
        <details open>
          <summary className="cursor-pointer text-[11px] uppercase tracking-[0.12em] text-muted2 font-semibold mb-2 hover:text-text select-none">
            Starter examples (click to pre-fill)
          </summary>
          <div className="grid grid-cols-1 gap-2 mt-2">
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
        </details>
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
                <label className="block text-[11px] uppercase tracking-[0.12em] text-muted2 font-semibold mb-1">
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

      {selected && (
        <div>
          <label className="block text-[11px] uppercase tracking-[0.12em] text-muted2 font-semibold mb-2">
            Note (context for the chat log)
          </label>
          <textarea
            value={note}
            onChange={(e) => setNote(e.target.value)}
            rows={2}
            placeholder="Optional: what this run is for, what to look for in the output..."
            className="w-full bg-bg border border-border rounded p-3 text-sm resize-none focus:outline-none focus:border-accent"
          />
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
