import { useState } from "react";

interface Props {
  busy: boolean;
  onRun: (form: { filePath: string; outputPath: string; note: string }) => void;
}

export function FilePanel({ busy, onRun }: Props) {
  const [filePath, setFilePath] = useState<string | null>(null);
  const [outputPath, setOutputPath] = useState("");
  const [note, setNote] = useState("");

  const pick = async () => {
    const chosen = await window.testudo.openFile();
    if (chosen) {
      setFilePath(chosen);
      if (!outputPath) {
        const base = chosen.split("/").pop() ?? "doc";
        setOutputPath(`/tmp/testudo-${base}.debrief.md`);
      }
    }
  };

  const submit = () => {
    if (!filePath) return;
    onRun({ filePath, outputPath, note });
  };

  return (
    <section className="flex flex-col h-full p-5 gap-4">
      <div>
        <label className="block text-xs uppercase text-muted tracking-wider mb-2">
          Document
        </label>
        <div className="flex gap-3 items-center">
          <button
            type="button"
            onClick={pick}
            className="px-3 py-2 rounded bg-bg border border-border hover:border-accent text-sm"
          >
            Pick file
          </button>
          <span className="flex-1 text-sm text-muted truncate">
            {filePath ?? "No file selected. PDF, DOCX, PPTX, HTML, TXT, MD, JSON."}
          </span>
        </div>
      </div>

      <div>
        <label className="block text-xs uppercase text-muted tracking-wider mb-2">
          Output path
        </label>
        <input
          type="text"
          value={outputPath}
          onChange={(e) => setOutputPath(e.target.value)}
          placeholder="/tmp/testudo-debrief.md"
          className="w-full bg-bg border border-border rounded px-3 py-2 text-sm focus:outline-none focus:border-accent"
        />
      </div>

      <div className="flex-1 flex flex-col">
        <label className="block text-xs uppercase text-muted tracking-wider mb-2">
          Note (context for the chat log)
        </label>
        <textarea
          value={note}
          onChange={(e) => setNote(e.target.value)}
          rows={4}
          placeholder="Optional: what to do with this document..."
          className="flex-1 w-full bg-bg border border-border rounded p-3 text-sm resize-none focus:outline-none focus:border-accent"
        />
      </div>

      <button
        type="button"
        onClick={submit}
        disabled={busy || !filePath || !outputPath}
        className="self-end px-5 py-2 rounded bg-accent text-white text-sm font-medium disabled:opacity-40 disabled:cursor-not-allowed"
      >
        {busy ? "Running..." : "Sanitise and summarise"}
      </button>
    </section>
  );
}
