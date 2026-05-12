import { useState } from "react";

export interface RecommendedModel {
  id: string;
  label: string;
  hint: string;
  pullCommand: string;
}

export const MODEL_GROUPS: Array<{ title: string; models: RecommendedModel[] }> = [
  {
    title: "Cloud (Ollama Cloud, signin required)",
    models: [
      {
        id: "minimax-m2.7:cloud",
        label: "minimax-m2.7",
        hint: "default. long context, careful summaries",
        pullCommand: "ollama signin",
      },
      {
        id: "mistral-large-3:675b-cloud",
        label: "mistral-large-3 (675b)",
        hint: "general-purpose, large",
        pullCommand: "ollama signin",
      },
      {
        id: "qwen3-coder-next:cloud",
        label: "qwen3-coder-next",
        hint: "code-leaning, large context",
        pullCommand: "ollama signin",
      },
      {
        id: "gemini-3-flash-preview:cloud",
        label: "gemini-3-flash-preview",
        hint: "fast general-purpose",
        pullCommand: "ollama signin",
      },
      {
        id: "gpt-oss:120b-cloud",
        label: "gpt-oss (120b)",
        hint: "open-source large",
        pullCommand: "ollama signin",
      },
      {
        id: "devstral-2:123b-cloud",
        label: "devstral-2 (123b)",
        hint: "code-leaning large",
        pullCommand: "ollama signin",
      },
    ],
  },
  {
    title: "Local",
    models: [
      {
        id: "mistral:latest",
        label: "mistral",
        hint: "7B general-purpose, runs locally",
        pullCommand: "ollama pull mistral",
      },
      {
        id: "magistral:latest",
        label: "magistral",
        hint: "23B reasoning model, runs locally",
        pullCommand: "ollama pull magistral",
      },
      {
        id: "jan-code:latest",
        label: "jan-code",
        hint: "4.4B code-leaning, runs locally",
        pullCommand: "ollama pull jan-code",
      },
      {
        id: "devstral-small-2:24b-instruct-2512-q4_K_M",
        label: "devstral-small-2 (24b)",
        hint: "24B code-leaning, runs locally",
        pullCommand: "ollama pull devstral-small-2:24b-instruct-2512-q4_K_M",
      },
    ],
  },
];

export const DEFAULT_MODEL = "minimax-m2.7:cloud";

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
