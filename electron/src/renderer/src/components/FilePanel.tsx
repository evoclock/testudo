import { useState } from "react";

export interface RecommendedModel {
  id: string;
  label: string;
  hint: string;
  pullCommand: string;
}

export const MODEL_GROUPS: Array<{ title: string; models: RecommendedModel[] }> = [
  {
    title: "General",
    models: [
      {
        id: "minimax-m2.7",
        label: "minimax-m2.7",
        hint: "default. long context, careful summaries (cloud-served)",
        pullCommand: "ollama pull minimax-m2.7",
      },
      {
        id: "mistral-large-3",
        label: "mistral-large-3",
        hint: "general-purpose",
        pullCommand: "ollama pull mistral-large-3",
      },
      {
        id: "qwen3.5",
        label: "qwen3.5",
        hint: "general-purpose alternative",
        pullCommand: "ollama pull qwen3.5",
      },
    ],
  },
  {
    title: "Code",
    models: [
      {
        id: "qwen3-coder-next",
        label: "qwen3-coder-next",
        hint: "code-leaning, larger context",
        pullCommand: "ollama pull qwen3-coder-next",
      },
      {
        id: "fredrezones55/Jan-code",
        label: "Jan-code",
        hint: "small / fast; good for short coding tasks",
        pullCommand: "ollama pull fredrezones55/Jan-code",
      },
    ],
  },
  {
    title: "Specialised",
    models: [
      {
        id: "fredrezones55/chandra-ocr-2",
        label: "chandra-ocr-2",
        hint: "OCR over scanned documents",
        pullCommand: "ollama pull fredrezones55/chandra-ocr-2",
      },
      {
        id: "mathstral",
        label: "mathstral",
        hint: "maths-leaning reasoning",
        pullCommand: "ollama pull mathstral",
      },
    ],
  },
];

export const DEFAULT_MODEL = "minimax-m2.7";

interface Props {
  busy: boolean;
  ollamaAvailable: boolean;
  installedModels: string[];
  onRun: (form: {
    filePath: string;
    outputPath: string;
    model: string;
    note: string;
  }) => void;
}

export function FilePanel({ busy, ollamaAvailable, installedModels, onRun }: Props) {
  const [filePath, setFilePath] = useState<string | null>(null);
  const [outputPath, setOutputPath] = useState("");
  const [model, setModel] = useState(DEFAULT_MODEL);
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
    onRun({ filePath, outputPath, model, note });
  };

  const isInstalled = (id: string) =>
    installedModels.some((m) => m === id || m.startsWith(`${id}:`));

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
          Model{" "}
          {!ollamaAvailable && (
            <span className="text-amber-400 normal-case">
              (ollama offline; start `ollama serve` for this to work)
            </span>
          )}
        </label>
        <div className="space-y-3">
          {MODEL_GROUPS.map((group) => (
            <div key={group.title}>
              <div className="text-[10px] uppercase tracking-wider text-muted/80 mb-1">
                {group.title}
              </div>
              <div className="grid grid-cols-2 gap-2">
                {group.models.map((m) => {
                  const installed = isInstalled(m.id);
                  const selected = model === m.id;
                  return (
                    <button
                      key={m.id}
                      type="button"
                      onClick={() => setModel(m.id)}
                      className={`text-left px-3 py-2 rounded border text-sm ${
                        selected
                          ? "border-accent bg-bg"
                          : "border-border bg-bg hover:border-accent"
                      }`}
                      title={
                        installed
                          ? `Installed in your local Ollama`
                          : `Not installed locally. Run: ${m.pullCommand}`
                      }
                    >
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-text">{m.label}</span>
                        <span
                          className={`text-[10px] px-1.5 rounded ${
                            installed
                              ? "bg-green-700 text-white"
                              : "bg-bg text-muted border border-border"
                          }`}
                        >
                          {installed ? "installed" : "pull"}
                        </span>
                      </div>
                      <div className="text-xs text-muted">{m.hint}</div>
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
        <input
          type="text"
          value={model}
          onChange={(e) => setModel(e.target.value)}
          placeholder="or type any model name..."
          className="mt-2 w-full bg-bg border border-border rounded px-3 py-2 text-sm font-mono focus:outline-none focus:border-accent"
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
          rows={3}
          placeholder="Optional: what to do with this document..."
          className="flex-1 w-full bg-bg border border-border rounded p-3 text-sm resize-none focus:outline-none focus:border-accent"
        />
      </div>

      <button
        type="button"
        onClick={submit}
        disabled={busy || !filePath || !outputPath || !model}
        className="self-end px-5 py-2 rounded bg-accent text-white text-sm font-medium disabled:opacity-40 disabled:cursor-not-allowed"
      >
        {busy ? "Running..." : "Sanitise and summarise"}
      </button>
    </section>
  );
}
