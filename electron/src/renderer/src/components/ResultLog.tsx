import { useState } from "react";
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

interface ChatBlock {
  text: string;
  attachments: string[];
}

function extractChatBlock(meta: RunResponse | undefined | null): ChatBlock | null {
  if (!meta) return null;
  for (const step of Object.values(meta.results)) {
    const out = step.output as Record<string, unknown> | null;
    if (!out || out.channel !== "chat") continue;
    const text = typeof out.text === "string" ? out.text : "";
    const attachments = Array.isArray(out.attachments)
      ? (out.attachments.filter((a) => typeof a === "string") as string[])
      : [];
    if (text || attachments.length > 0) {
      return { text, attachments };
    }
  }
  return null;
}

const STATUS_DOT: Record<string, string> = {
  user: "bg-yellow-500",
  system: "bg-green-500",
  error: "bg-red-500",
  info: "bg-muted2",
};

const STATUS_LABEL_TEXT: Record<string, string> = {
  user: "queued",
  system: "completed",
  error: "failed",
  info: "info",
};

const STATUS_LABEL_COLOUR: Record<string, string> = {
  user: "text-yellow-400",
  system: "text-green-400",
  error: "text-red-400",
  info: "text-muted2",
};

function shortHeadline(entry: LogEntry): string {
  if (entry.meta) return entry.meta.workflow_name;
  return entry.text.split("\n")[0].slice(0, 80);
}

function formatTime(): string {
  const d = new Date();
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

function ActivityRow({ entry }: { entry: LogEntry }) {
  const [open, setOpen] = useState(entry.kind === "error");
  const counts = countFindings(entry.meta);
  const total = counts.critical + counts.high + counts.medium + counts.low;
  const stepResults = entry.meta?.results ?? {};
  const chat = extractChatBlock(entry.meta);
  const dot = STATUS_DOT[entry.kind];
  const labelText = entry.meta ? entry.meta.status : STATUS_LABEL_TEXT[entry.kind];
  const labelColour = entry.kind === "error" ? "text-red-400" : entry.meta?.status === "completed" ? "text-green-400" : STATUS_LABEL_COLOUR[entry.kind];
  const headline = shortHeadline(entry);
  const isExpandable = Boolean(entry.meta || entry.note || chat);

  return (
    <div
      className={`rounded border ${
        entry.kind === "error" ? "border-red-500/40 bg-red-500/5" : "border-border bg-panel"
      } ${isExpandable ? "hover:border-muted2 cursor-pointer" : ""}`}
    >
      <div
        className="flex items-center gap-2 px-2.5 py-1.5"
        onClick={() => isExpandable && setOpen((v) => !v)}
      >
        <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dot}`} />
        <span className="text-xs text-text truncate">{headline}</span>
        <span className={`text-[10px] font-mono ${labelColour}`}>{labelText}</span>
        {total > 0 && (
          <div className="flex items-center gap-1">
            {counts.critical > 0 && (
              <span className={`px-1 rounded text-[9px] ${SEVERITY_COLOUR.CRITICAL}`}>
                {counts.critical}c
              </span>
            )}
            {counts.high > 0 && (
              <span className={`px-1 rounded text-[9px] ${SEVERITY_COLOUR.HIGH}`}>
                {counts.high}h
              </span>
            )}
          </div>
        )}
        <span className="text-[10px] text-muted2 ml-auto font-mono">
          {formatTime()}
        </span>
        {isExpandable && (
          <svg
            className={`w-3.5 h-3.5 text-muted2 shrink-0 transition-transform ${open ? "rotate-180" : ""}`}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <polyline points="6 9 12 15 18 9" />
          </svg>
        )}
      </div>

      {open && isExpandable && (
        <div className="px-3 py-2.5 border-t border-border/60 space-y-2">
          {entry.note && (
            <div className="text-xs text-muted italic">{entry.note}</div>
          )}
          {chat && (
            <div className="p-2 rounded bg-bg/60 border border-border">
              {chat.text && (
                <div className="text-xs whitespace-pre-wrap text-text">{chat.text}</div>
              )}
              {chat.attachments.length > 0 && (
                <div className="mt-1.5 text-[11px] text-muted2">
                  Attachment{chat.attachments.length > 1 ? "s" : ""}:
                  <ul className="mt-0.5 space-y-0.5">
                    {chat.attachments.map((a) => (
                      <li key={a} className="font-mono text-text/80 break-all">
                        {a}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
          {entry.meta && (
            <div className="space-y-1.5">
              <details className="text-[11px]">
                <summary className="cursor-pointer text-muted2 hover:text-text">
                  {Object.keys(stepResults).length} step
                  {Object.keys(stepResults).length === 1 ? "" : "s"}
                </summary>
                <ol className="mt-1.5 space-y-1">
                  {Object.entries(stepResults).map(([id, res]) => (
                    <li key={id} className="flex items-start gap-2">
                      <span
                        className={`mt-0.5 px-1.5 rounded text-[9px] ${
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
              <div className="flex items-center gap-2 text-[10px] text-muted2 flex-wrap">
                <span className="font-mono">run {entry.meta.run_id}</span>
                {entry.meta.audit_log && (
                  <>
                    <span>·</span>
                    <span className="font-mono break-all">audit: {entry.meta.audit_log}</span>
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function ResultLog({ entries }: Props) {
  return (
    <div className="flex-1 overflow-y-auto p-3 space-y-1.5">
      {entries.map((entry, i) => (
        <ActivityRow key={i} entry={entry} />
      ))}
    </div>
  );
}
