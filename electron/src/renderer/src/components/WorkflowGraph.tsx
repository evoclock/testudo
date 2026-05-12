import { useMemo } from "react";
import {
  Background,
  Controls,
  ReactFlow,
  type Edge,
  type Node,
} from "reactflow";
import "reactflow/dist/style.css";
import type { WorkflowSummary } from "../lib/api";

interface Props {
  workflow: WorkflowSummary | null;
}

export function WorkflowGraph({ workflow }: Props) {
  const nodes = useMemo<Node[]>(() => {
    if (!workflow) return [];
    return Array.from({ length: workflow.step_count }, (_, i) => ({
      id: `step-${i}`,
      data: { label: `step ${i + 1}` },
      position: { x: 60 + i * 180, y: 80 },
      style: {
        background: "#2a2a32",
        color: "#e5e5ec",
        border: "1px solid #3a3a44",
      },
    }));
  }, [workflow]);

  const edges = useMemo<Edge[]>(() => {
    if (!workflow) return [];
    return Array.from({ length: workflow.step_count - 1 }, (_, i) => ({
      id: `e-${i}`,
      source: `step-${i}`,
      target: `step-${i + 1}`,
      style: { stroke: "#5e9bd1" },
    }));
  }, [workflow]);

  if (!workflow) {
    return (
      <div className="flex items-center justify-center h-full text-muted text-sm">
        Select a workflow to render its graph.
      </div>
    );
  }

  return (
    <div className="w-full h-full">
      <ReactFlow nodes={nodes} edges={edges} fitView>
        <Background color="#3a3a44" />
        <Controls />
      </ReactFlow>
    </div>
  );
}
