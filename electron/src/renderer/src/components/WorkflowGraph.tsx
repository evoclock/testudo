import { useMemo } from "react";
import {
  Background,
  Controls,
  ReactFlow,
  type Edge,
  type Node,
} from "reactflow";
import "reactflow/dist/style.css";
import type { RunResponse, WorkflowSummary } from "../lib/api";

interface Props {
  workflow: WorkflowSummary | null;
  lastRun: RunResponse | null;
}

type Status = "pending" | "ok" | "fail" | "skip";

function statusFor(
  stepId: string,
  lastRun: RunResponse | null,
  workflowName: string | undefined,
): Status {
  if (!lastRun || lastRun.workflow_name !== workflowName) return "pending";
  const step = lastRun.results[stepId];
  if (!step) return "pending";
  if (step.error) return "fail";
  if (step.skipped) return "skip";
  return "ok";
}

const STATUS_STYLE: Record<Status, { background: string; color: string; border: string }> = {
  pending: { background: "#2a2a32", color: "#e5e5ec", border: "1px solid #3a3a44" },
  ok: { background: "#14532d", color: "#dcfce7", border: "1px solid #22c55e" },
  fail: { background: "#7f1d1d", color: "#fee2e2", border: "1px solid #ef4444" },
  skip: { background: "#1f1f24", color: "#9b9bab", border: "1px dashed #9b9bab" },
};

export function WorkflowGraph({ workflow, lastRun }: Props) {
  const nodes = useMemo<Node[]>(() => {
    if (!workflow) return [];
    const cols = Math.max(1, Math.ceil(Math.sqrt(workflow.steps.length)));
    return workflow.steps.map((step, i) => {
      const col = i % cols;
      const row = Math.floor(i / cols);
      const status = statusFor(step.id, lastRun, workflow.name);
      return {
        id: step.id,
        data: { label: `${step.id}\n(${step.uses})` },
        position: { x: 30 + col * 200, y: 30 + row * 90 },
        style: {
          ...STATUS_STYLE[status],
          fontSize: 11,
          padding: 8,
          borderRadius: 6,
          whiteSpace: "pre-line" as const,
          width: 180,
        },
      };
    });
  }, [workflow, lastRun]);

  const edges = useMemo<Edge[]>(() => {
    if (!workflow) return [];
    const out: Edge[] = [];
    for (const step of workflow.steps) {
      for (const dep of step.needs) {
        out.push({
          id: `${dep}-${step.id}`,
          source: dep,
          target: step.id,
          style: { stroke: "#5e9bd1" },
        });
      }
    }
    return out;
  }, [workflow]);

  if (!workflow) {
    return (
      <div className="flex items-center justify-center h-full text-muted text-xs">
        No workflow staged. Pick a mode above to load a workflow's DAG.
      </div>
    );
  }

  return (
    <div className="w-full h-full">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        proOptions={{ hideAttribution: true }}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
      >
        <Background color="#3a3a44" />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
