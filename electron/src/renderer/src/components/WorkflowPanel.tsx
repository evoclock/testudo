import { useEffect, useMemo, useState } from "react";
import type { WorkflowSummary } from "../lib/api";

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
  onRun: (workflow: WorkflowSummary, inputs: Record<string, unknown>) => void;
  onSelectionChange?: (workflowName: string) => void;
}

export function WorkflowPanel({ workflows, busy, onRun, onSelectionChange }: Props) {
  const [selectedName, setSelectedName] = useState<string>("");
  const [form, setForm] = useState<Record<string, unknown>>({});

  const selected = useMemo(
    () => workflows.find((w) => w.name === selectedName) ?? null,
    [workflows, selectedName],
  );

  useEffect(() => {
    onSelectionChange?.(selectedName);
  }, [selectedName, onSelectionChange]);

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
        // Pre-fill an output path so the user doesn't have to invent one
        seed[key] = `/tmp/testudo-${selected.name}.md`;
      } else if (spec.type === "array") {
        seed[key] = [];
      }
    }
    setForm(seed);
  }, [selected]);

  const placeholderFor = (key: string, spec: InputSpec): string => {
    if (spec.default !== undefined) return `default: ${JSON.stringify(spec.default)}`;
    if (spec.type === "array") return "[]";
    if (spec.type === "integer" || spec.type === "number") return "0";
    if (key === "query") return "SELECT * FROM samples.bakehouse.sales_transactions LIMIT 10";
    if (key === "url") return "https://example.com/file.md";
    if (key.includes("path")) return "/tmp/testudo-output.md";
    return spec.required ? "(required)" : "(optional)";
  };

  const updateField = (key: string, value: unknown) => {
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  const pickFor = async (key: string) => {
    const chosen = await window.testudo.openFile();
    if (chosen) updateField(key, chosen);
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
      </div>

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
                <div className="flex gap-2">
                  <input
                    type={isNumber ? "number" : "text"}
                    value={
                      isArray
                        ? JSON.stringify(v ?? [])
                        : v == null
                          ? ""
                          : String(v)
                    }
                    onChange={(e) => {
                      if (isArray) {
                        try {
                          updateField(key, JSON.parse(e.target.value));
                        } catch {
                          updateField(key, e.target.value);
                        }
                      } else if (isNumber) {
                        updateField(key, Number(e.target.value));
                      } else {
                        updateField(key, e.target.value);
                      }
                    }}
                    placeholder={placeholderFor(key, spec)}
                    className="flex-1 bg-bg border border-border rounded px-3 py-2 text-sm focus:outline-none focus:border-accent"
                  />
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
