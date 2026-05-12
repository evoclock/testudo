import { useState } from "react";

interface Props {
  busy: boolean;
  onRun: (form: {
    url: string;
    outputPath: string;
    maxBytes: number;
    note: string;
  }) => void;
}

export function UrlPanel({ busy, onRun }: Props) {
  const [url, setUrl] = useState("");
  const [outputPath, setOutputPath] = useState("/tmp/testudo-url-debrief.md");
  const [maxBytes, setMaxBytes] = useState(10 * 1024 * 1024);
  const [note, setNote] = useState("");

  const submit = () => {
    if (!url.trim()) return;
    onRun({ url: url.trim(), outputPath, maxBytes, note });
  };

  return (
    <section className="flex flex-col h-full p-5 gap-4">
      <div>
        <label className="block text-xs uppercase text-muted tracking-wider mb-2">
          URL
        </label>
        <input
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com/article"
          className="w-full bg-bg border border-border rounded px-3 py-2 text-sm focus:outline-none focus:border-accent"
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
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
            Max bytes
          </label>
          <input
            type="number"
            value={maxBytes}
            onChange={(e) => setMaxBytes(Number(e.target.value))}
            className="w-full bg-bg border border-border rounded px-3 py-2 text-sm focus:outline-none focus:border-accent"
          />
        </div>
      </div>

      <div className="flex-1 flex flex-col">
        <label className="block text-xs uppercase text-muted tracking-wider mb-2">
          Note (context for the chat log)
        </label>
        <textarea
          value={note}
          onChange={(e) => setNote(e.target.value)}
          rows={4}
          placeholder="Optional: what to extract from this URL..."
          className="flex-1 w-full bg-bg border border-border rounded p-3 text-sm resize-none focus:outline-none focus:border-accent"
        />
      </div>

      <button
        type="button"
        onClick={submit}
        disabled={busy || !url.trim()}
        className="self-end px-5 py-2 rounded bg-accent text-white text-sm font-medium disabled:opacity-40 disabled:cursor-not-allowed"
      >
        {busy ? "Running..." : "Fetch and sanitise"}
      </button>
    </section>
  );
}
