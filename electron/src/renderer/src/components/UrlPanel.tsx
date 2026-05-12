import { useMemo, useState } from "react";

interface Props {
  busy: boolean;
  onRun: (form: {
    url: string;
    outputPath: string;
    maxBytes: number;
    note: string;
  }) => void;
}

interface UrlVerdict {
  resolvedUrl: string;
  rewrote: boolean;
  rewriteHint: string | null;
  error: string | null;
}

const DRIVE_FILE_RE = /^https:\/\/drive\.google\.com\/file\/d\/([a-zA-Z0-9_-]{20,})/;
const DRIVE_DOCS_RE = /^https:\/\/docs\.google\.com\/[^/]+\/d\/([a-zA-Z0-9_-]{20,})/;
const DRIVE_OPEN_RE = /^https:\/\/drive\.google\.com\/open\?id=([a-zA-Z0-9_-]{20,})/;
const DRIVE_FOLDER_RE = /^https:\/\/drive\.google\.com\/(?:drive\/u\/\d+\/)?folders\//;

function classify(raw: string): UrlVerdict {
  const url = raw.trim();
  if (!url) {
    return { resolvedUrl: "", rewrote: false, rewriteHint: null, error: null };
  }
  if (DRIVE_FOLDER_RE.test(url)) {
    return {
      resolvedUrl: url,
      rewrote: false,
      rewriteHint: null,
      error:
        "That is a Drive FOLDER URL. The fetcher gets one file at a time. Open a single file inside the folder, Share -> Anyone with the link, and paste THAT URL here.",
    };
  }
  for (const re of [DRIVE_FILE_RE, DRIVE_DOCS_RE, DRIVE_OPEN_RE]) {
    const m = url.match(re);
    if (m) {
      const fileId = m[1];
      const direct = `https://drive.google.com/uc?export=download&id=${fileId}`;
      return {
        resolvedUrl: direct,
        rewrote: true,
        rewriteHint: `Rewrote Drive share URL to direct-download form (file id: ${fileId.slice(0, 8)}...).`,
        error: null,
      };
    }
  }
  return { resolvedUrl: url, rewrote: false, rewriteHint: null, error: null };
}

export function UrlPanel({ busy, onRun }: Props) {
  const [url, setUrl] = useState("");
  const [outputPath, setOutputPath] = useState("/tmp/testudo-url-debrief.md");
  const [maxBytes, setMaxBytes] = useState(10 * 1024 * 1024);
  const [note, setNote] = useState("");

  const verdict = useMemo(() => classify(url), [url]);

  const submit = () => {
    if (!verdict.resolvedUrl || verdict.error) return;
    onRun({ url: verdict.resolvedUrl, outputPath, maxBytes, note });
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
          placeholder="https://example.com/article  (Drive share URLs auto-rewrite)"
          className="w-full bg-bg border border-border rounded px-3 py-2 text-sm focus:outline-none focus:border-accent"
        />
        {verdict.rewriteHint && (
          <p className="text-[11px] text-green-300 mt-1">
            {verdict.rewriteHint} Fetching:{" "}
            <span className="font-mono">{verdict.resolvedUrl}</span>
          </p>
        )}
        {verdict.error && (
          <p className="text-[11px] text-red-300 mt-1">{verdict.error}</p>
        )}
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
        disabled={busy || !verdict.resolvedUrl || verdict.error !== null}
        className="self-end px-5 py-2 rounded bg-accent text-white text-sm font-medium disabled:opacity-40 disabled:cursor-not-allowed"
      >
        {busy ? "Running..." : "Fetch and sanitise"}
      </button>
    </section>
  );
}
