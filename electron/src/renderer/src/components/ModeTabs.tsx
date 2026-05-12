import type { Mode } from "../lib/modes";

interface Props {
  active: Mode;
  onSelect: (mode: Mode) => void;
}

const TABS: Array<{ id: Mode; label: string; hint: string }> = [
  { id: "file", label: "File", hint: "PDF / DOCX / PPTX / HTML / TXT / MD" },
  { id: "url", label: "URL", hint: "Fetch an HTTPS resource" },
  { id: "database", label: "Database", hint: "DuckDB now, Databricks pending" },
  { id: "workflow", label: "Workflow", hint: "Run an arbitrary workflow.json" },
];

export function ModeTabs({ active, onSelect }: Props) {
  return (
    <nav className="flex items-stretch border-b border-border bg-panel">
      {TABS.map((tab) => {
        const isActive = active === tab.id;
        return (
          <button
            key={tab.id}
            type="button"
            onClick={() => onSelect(tab.id)}
            className={`flex-1 px-5 py-3 text-left border-r border-border last:border-r-0 ${
              isActive
                ? "bg-bg text-text border-t-2 border-t-accent"
                : "text-muted hover:text-text hover:bg-bg/40"
            }`}
          >
            <div className="text-sm font-medium">{tab.label}</div>
            <div className="text-xs text-muted">{tab.hint}</div>
          </button>
        );
      })}
    </nav>
  );
}
