import type { RunResponse } from "../lib/api";

export interface LogEntry {
  kind: "info" | "user" | "system" | "error";
  text: string;
  meta?: RunResponse | null;
  note?: string;
}

interface Props {
  entries: LogEntry[];
}

const SEVERITY_COLOUR: Record<string, string> = {
  CRITICAL: "bg-red-700 text-white",
  HIGH: "bg-red-500 text-white",
  MEDIUM: "bg-amber-500 text-black",
  LOW: "bg-yellow-300 text-black",
  INFO: "bg-blue-400 text-black",
};

function countFindings(meta: RunResponse | undefined | null): {
  critical: number;
  high: number;
  medium: number;
  low: number;
} {
  const acc = { critical: 0, high: 0, medium: 0, low: 0 };
  if (!meta) return acc;
  for (const step of Object.values(meta.results)) {
    const out = (step.output ?? {}) as Record<string, unknown>;
    const findings = (out.findings as Array<{ severity: number }> | undefined) ?? [];
    for (const f of findings) {
      if (f.severity === 4) acc.critical += 1;
      else if (f.severity === 3) acc.high += 1;
      else if (f.severity === 2) acc.medium += 1;
      else if (f.severity === 1) acc.low += 1;
    }
  }
  return acc;
}

export function ResultLog({ entries }: Props) {
  return (
    <div className="flex-1 overflow-y-auto p-5 space-y-3">
      {entries.map((entry, i) => {
        const counts = countFindings(entry.meta);
        const total = counts.critical + counts.high + counts.medium + counts.low;
        const stepResults = entry.meta?.results ?? {};

        return (
          <div
            key={i}
            className={`p-3 rounded border-l-4 bg-panel ${
              entry.kind === "user"
                ? "border-yellow-600"
                : entry.kind === "error"
                  ? "border-red-500"
                  : "border-accent"
            }`}
          >
            <div className="text-sm whitespace-pre-wrap">{entry.text}</div>

            {entry.note && (
              <div className="text-xs text-muted mt-2 italic">{entry.note}</div>
            )}

            {entry.meta && (
              <div className="mt-3 space-y-2">
                <div className="flex items-center gap-2 flex-wrap text-xs">
                  <span className="text-muted">run {entry.meta.run_id}</span>
                  <span
                    className={`px-2 py-0.5 rounded ${
                      entry.meta.status === "completed"
                        ? "bg-green-700 text-white"
                        : "bg-red-700 text-white"
                    }`}
                  >
                    {entry.meta.status}
                  </span>
                  {total > 0 && (
                    <>
                      {counts.critical > 0 && (
                        <span className={`px-2 py-0.5 rounded ${SEVERITY_COLOUR.CRITICAL}`}>
                          {counts.critical} critical
                        </span>
                      )}
                      {counts.high > 0 && (
                        <span className={`px-2 py-0.5 rounded ${SEVERITY_COLOUR.HIGH}`}>
                          {counts.high} high
                        </span>
                      )}
                      {counts.medium > 0 && (
                        <span className={`px-2 py-0.5 rounded ${SEVERITY_COLOUR.MEDIUM}`}>
                          {counts.medium} medium
                        </span>
                      )}
                      {counts.low > 0 && (
                        <span className={`px-2 py-0.5 rounded ${SEVERITY_COLOUR.LOW}`}>
                          {counts.low} low
                        </span>
                      )}
                    </>
                  )}
                </div>

                <details className="text-xs">
                  <summary className="cursor-pointer text-muted hover:text-text">
                    {Object.keys(stepResults).length} step
                    {Object.keys(stepResults).length === 1 ? "" : "s"} (click to expand)
                  </summary>
                  <ol className="mt-2 space-y-1">
                    {Object.entries(stepResults).map(([id, res]) => (
                      <li key={id} className="flex items-start gap-2">
                        <span
                          className={`mt-0.5 px-1.5 rounded text-[10px] ${
                            res.error
                              ? "bg-red-700 text-white"
                              : res.skipped
                                ? "bg-bg text-muted border border-border"
                                : "bg-green-700 text-white"
                          }`}
                        >
                          {res.error ? "FAIL" : res.skipped ? "SKIP" : "OK"}
                        </span>
                        <span className="font-mono text-muted">{id}</span>
                        {res.error && <span className="text-red-300">{res.error}</span>}
                      </li>
                    ))}
                  </ol>
                </details>

                {entry.meta.audit_log && (
                  <div className="text-xs text-muted">
                    audit:&nbsp;
                    <span className="font-mono text-text/80 break-all">
                      {entry.meta.audit_log}
                    </span>
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
