import type { WorkflowSummary } from "../lib/api";

interface Props {
  workflows: WorkflowSummary[];
  selected: WorkflowSummary | null;
  onSelect: (wf: WorkflowSummary) => void;
}

export function Sidebar({ workflows, selected, onSelect }: Props) {
  return (
    <aside className="bg-panel border-r border-border p-4 overflow-y-auto h-full">
      <h2 className="text-xs uppercase text-muted mb-3 tracking-wider">Workflows</h2>
      <ul className="space-y-2">
        {workflows.length === 0 && (
          <li className="text-muted text-sm">No workflows discovered.</li>
        )}
        {workflows.map((wf) => (
          <li key={wf.path}>
            <button
              type="button"
              onClick={() => onSelect(wf)}
              className={`w-full text-left px-3 py-2 rounded border ${
                selected?.path === wf.path
                  ? "border-accent bg-bg"
                  : "border-border hover:border-accent bg-bg"
              }`}
            >
              <div className="text-sm font-medium">{wf.name}</div>
              <div className="text-xs text-muted">{wf.step_count} steps</div>
            </button>
          </li>
        ))}
      </ul>
    </aside>
  );
}
