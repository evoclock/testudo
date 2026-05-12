import { useState } from "react";
import type { RunResponse } from "../lib/api";

export interface Message {
  role: "user" | "system";
  text: string;
  meta?: RunResponse | null;
}

interface Props {
  messages: Message[];
  attachedFile: string | null;
  onSubmit: (text: string) => void;
  onAttach: () => void;
}

export function Chat({ messages, attachedFile, onSubmit, onAttach }: Props) {
  const [draft, setDraft] = useState("");

  const send = () => {
    const trimmed = draft.trim();
    if (!trimmed) return;
    onSubmit(trimmed);
    setDraft("");
  };

  return (
    <section className="flex flex-col h-full">
      <div className="flex-1 overflow-y-auto p-5 space-y-3">
        {messages.map((msg, i) => (
          <div
            key={i}
            className={`p-3 rounded border-l-4 bg-panel ${
              msg.role === "user" ? "border-yellow-600" : "border-accent"
            }`}
          >
            <div className="text-sm whitespace-pre-wrap">{msg.text}</div>
            {msg.meta && (
              <pre className="text-xs text-muted mt-2 overflow-x-auto">
                {JSON.stringify(msg.meta.results, null, 2)}
              </pre>
            )}
          </div>
        ))}
      </div>
      <footer className="border-t border-border bg-panel p-4 space-y-3">
        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          rows={3}
          placeholder="Ask something about your file or run a workflow..."
          className="w-full bg-bg border border-border rounded p-3 text-sm resize-none focus:outline-none focus:border-accent"
        />
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={onAttach}
            className="px-3 py-2 rounded bg-bg border border-border hover:border-accent text-sm"
          >
            Attach file
          </button>
          <span className="flex-1 text-xs text-muted truncate">
            {attachedFile ?? "No file attached."}
          </span>
          <button
            type="button"
            onClick={send}
            className="px-4 py-2 rounded bg-accent text-white text-sm font-medium"
          >
            Send
          </button>
        </div>
      </footer>
    </section>
  );
}
