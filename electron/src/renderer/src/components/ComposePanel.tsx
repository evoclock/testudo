import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Background,
  Controls,
  ReactFlow,
  addEdge,
  applyEdgeChanges,
  applyNodeChanges,
  type Connection,
  type Edge,
  type EdgeChange,
  type Node,
  type NodeChange,
} from "reactflow";
import "reactflow/dist/style.css";
import type {
  BridgeClient,
  ToolSummary,
  WorkflowDraft,
  WorkflowDraftStep,
} from "../lib/api";

interface Props {
  client: BridgeClient | null;
  busy: boolean;
  onSaved: (name: string, path: string) => void;
  onError: (message: string) => void;
}

interface NodeData {
  uses: string;
  with: Record<string, unknown>;
}

let nodeCounter = 0;
const nextId = () => `step_${++nodeCounter}`;

export function ComposePanel({ client, busy, onSaved, onError }: Props) {
  const [tools, setTools] = useState<ToolSummary[]>([]);
  const [name, setName] = useState("my-workflow");
  const [description, setDescription] = useState("");
  const [nodes, setNodes] = useState<Node<NodeData>[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!client) return;
    client
      .listTools()
      .then(setTools)
      .catch((err) => onError(`failed to load tools: ${(err as Error).message}`));
  }, [client, onError]);

  const onNodesChange = useCallback(
    (changes: NodeChange[]) => setNodes((ns) => applyNodeChanges(changes, ns)),
    [],
  );
  const onEdgesChange = useCallback(
    (changes: EdgeChange[]) => setEdges((es) => applyEdgeChanges(changes, es)),
    [],
  );
  const onConnect = useCallback(
    (connection: Connection) =>
      setEdges((es) =>
        addEdge(
          { ...connection, style: { stroke: "#5e9bd1" }, animated: false },
          es,
        ),
      ),
    [],
  );

  const addTool = (tool: ToolSummary) => {
    const id = nextId();
    const seed: Record<string, unknown> = {};
    for (const p of tool.params) {
      if (p.has_default) seed[p.name] = p.default;
    }
    setNodes((ns) => [
      ...ns,
      {
        id,
        data: { uses: tool.name, with: seed },
        position: { x: 60 + (ns.length % 4) * 220, y: 40 + Math.floor(ns.length / 4) * 110 },
        style: {
          background: "#2a2a32",
          color: "#e5e5ec",
          border: "1px solid #3a3a44",
          fontSize: 11,
          padding: 8,
          borderRadius: 6,
          width: 200,
          whiteSpace: "pre-line" as const,
        },
      },
    ]);
  };

  const selected = useMemo(
    () => nodes.find((n) => n.id === selectedId) ?? null,
    [nodes, selectedId],
  );
  const selectedTool = useMemo(
    () => (selected ? tools.find((t) => t.name === selected.data.uses) ?? null : null),
    [selected, tools],
  );

  const updateSelectedWith = (key: string, value: unknown) => {
    if (!selected) return;
    setNodes((ns) =>
      ns.map((n) =>
        n.id === selected.id ? { ...n, data: { ...n.data, with: { ...n.data.with, [key]: value } } } : n,
      ),
    );
  };

  const renameSelectedId = (newId: string) => {
    if (!selected || !newId || newId === selected.id) return;
    if (nodes.some((n) => n.id === newId)) return;
    setNodes((ns) =>
      ns.map((n) => (n.id === selected.id ? { ...n, id: newId } : n)),
    );
    setEdges((es) =>
      es.map((e) => ({
        ...e,
        source: e.source === selected.id ? newId : e.source,
        target: e.target === selected.id ? newId : e.target,
      })),
    );
    setSelectedId(newId);
  };

  const deleteSelected = () => {
    if (!selected) return;
    setNodes((ns) => ns.map((n) => ({ ...n })).filter((n) => n.id !== selected.id));
    setEdges((es) =>
      es.filter((e) => e.source !== selected.id && e.target !== selected.id),
    );
    setSelectedId(null);
  };

  const draft = useMemo<WorkflowDraft>(() => {
    const steps: WorkflowDraftStep[] = nodes.map((n) => {
      const needs = edges
        .filter((e) => e.target === n.id)
        .map((e) => e.source);
      return { id: n.id, uses: n.data.uses, needs, with: n.data.with };
    });
    return { name, description: description || undefined, inputs: {}, steps };
  }, [nodes, edges, name, description]);

  const canSave = name.trim().length > 0 && nodes.length > 0 && !saving && !busy;

  const save = async () => {
    if (!client) {
      onError("bridge not ready");
      return;
    }
    setSaving(true);
    try {
      const resp = await client.saveWorkflow(draft);
      onSaved(resp.name, resp.path);
    } catch (err) {
      onError(`save failed: ${(err as Error).message}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <section className="flex h-full">
      <aside className="w-56 border-r border-border bg-panel/70 flex flex-col h-full">
        <div className="px-3 py-2 text-xs uppercase tracking-wider text-muted border-b border-border">
          Tool palette
        </div>
        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {tools.length === 0 && (
            <div className="text-xs text-muted p-2">
              Loading registered tools from the bridge...
            </div>
          )}
          {tools.map((tool) => (
            <button
              key={tool.name}
              type="button"
              onClick={() => addTool(tool)}
              className="w-full text-left px-2 py-1.5 rounded text-xs bg-bg border border-border hover:border-accent"
              title={tool.doc ?? tool.name}
            >
              <div className="font-mono">{tool.name}</div>
              <div className="text-muted/80 truncate">
                {tool.params.length} param{tool.params.length === 1 ? "" : "s"}
              </div>
            </button>
          ))}
        </div>
      </aside>

      <div className="flex-1 flex flex-col h-full">
        <div className="flex items-center gap-3 px-4 py-3 border-b border-border bg-panel">
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="workflow-name (kebab-case)"
            className="bg-bg border border-border rounded px-2 py-1 text-sm focus:outline-none focus:border-accent"
          />
          <input
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Description (optional)"
            className="flex-1 bg-bg border border-border rounded px-2 py-1 text-sm focus:outline-none focus:border-accent"
          />
          <button
            type="button"
            onClick={save}
            disabled={!canSave}
            className="px-4 py-1.5 rounded bg-accent text-white text-sm font-medium disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {saving ? "Saving..." : "Save workflow"}
          </button>
        </div>

        <div className="flex-1 flex">
          <div className="flex-1 min-w-0">
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onConnect={onConnect}
              onNodeClick={(_, n) => setSelectedId(n.id)}
              proOptions={{ hideAttribution: true }}
              fitView
            >
              <Background color="#3a3a44" />
              <Controls />
            </ReactFlow>
          </div>

          <aside className="w-80 border-l border-border bg-panel/70 flex flex-col h-full overflow-hidden">
            <div className="px-3 py-2 text-xs uppercase tracking-wider text-muted border-b border-border">
              Node inspector
            </div>
            {!selected && (
              <div className="p-3 text-xs text-muted">
                Click a node in the canvas to edit its uses + with: params.
                Drag from one node's handle to another to add a needs edge.
              </div>
            )}
            {selected && selectedTool && (
              <div className="flex-1 overflow-y-auto p-3 space-y-3">
                <div>
                  <label className="block text-xs uppercase text-muted tracking-wider mb-1">
                    Step id
                  </label>
                  <input
                    type="text"
                    defaultValue={selected.id}
                    onBlur={(e) => renameSelectedId(e.target.value.trim())}
                    className="w-full bg-bg border border-border rounded px-2 py-1 text-sm focus:outline-none focus:border-accent"
                  />
                </div>
                <div>
                  <label className="block text-xs uppercase text-muted tracking-wider mb-1">
                    Uses
                  </label>
                  <div className="font-mono text-sm">{selectedTool.name}</div>
                  {selectedTool.doc && (
                    <p className="text-xs text-muted mt-1 whitespace-pre-line">
                      {selectedTool.doc}
                    </p>
                  )}
                </div>
                <div>
                  <label className="block text-xs uppercase text-muted tracking-wider mb-2">
                    With: params
                  </label>
                  <div className="space-y-2">
                    {selectedTool.params.length === 0 && (
                      <div className="text-xs text-muted">No params.</div>
                    )}
                    {selectedTool.params.map((p) => {
                      const v = selected.data.with[p.name];
                      return (
                        <div key={p.name}>
                          <label className="block text-[10px] uppercase text-muted tracking-wider mb-0.5">
                            {p.name}
                            {p.required && <span className="text-red-400 ml-1">*</span>}
                            <span className="text-muted/60 ml-2 normal-case">
                              ({p.annotation})
                            </span>
                          </label>
                          <input
                            type="text"
                            value={v == null ? "" : String(v)}
                            onChange={(e) => updateSelectedWith(p.name, e.target.value)}
                            placeholder={
                              p.has_default ? `default: ${String(p.default)}` : "required"
                            }
                            className="w-full bg-bg border border-border rounded px-2 py-1 text-xs font-mono focus:outline-none focus:border-accent"
                          />
                        </div>
                      );
                    })}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={deleteSelected}
                  className="w-full px-3 py-1.5 rounded bg-bg border border-red-500/40 text-red-300 text-xs hover:bg-red-900/30"
                >
                  Delete node
                </button>
              </div>
            )}
          </aside>
        </div>
      </div>
    </section>
  );
}
