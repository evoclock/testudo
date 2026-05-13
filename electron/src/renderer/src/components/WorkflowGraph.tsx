import { useMemo } from "react";
import {
  Background,
  Controls,
  Handle,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes,
} from "reactflow";
import "reactflow/dist/style.css";
import type { RunResponse, WorkflowSummary } from "../lib/api";

interface Props {
  workflow: WorkflowSummary | null;
  lastRun: RunResponse | null;
}

type Status = "pending" | "ok" | "fail" | "skip";

interface TestudoNodeData {
  toolName: string;
  stepId: string;
  status: Status;
  durationMs: number | null;
}

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

function durationFor(
  stepId: string,
  lastRun: RunResponse | null,
  workflowName: string | undefined,
): number | null {
  if (!lastRun || lastRun.workflow_name !== workflowName) return null;
  const step = lastRun.results[stepId] as
    | { duration_ms?: number; durationMs?: number }
    | undefined;
  if (!step) return null;
  if (typeof step.duration_ms === "number") return step.duration_ms;
  if (typeof step.durationMs === "number") return step.durationMs;
  return null;
}

const STATUS_STRIPE: Record<Status, string> = {
  pending: "#3a3a44",
  ok: "#3fa66d",
  fail: "#ef4444",
  skip: "#9b9bab",
};

const STATUS_LABEL: Record<Status, string> = {
  pending: "PENDING",
  ok: "OK",
  fail: "FAIL",
  skip: "SKIP",
};

const STATUS_TEXT: Record<Status, string> = {
  pending: "#9b9bab",
  ok: "#3fa66d",
  fail: "#ef4444",
  skip: "#9b9bab",
};

function TestudoNode({ data }: NodeProps<TestudoNodeData>) {
  const stripeColor = STATUS_STRIPE[data.status];
  const statusColor = STATUS_TEXT[data.status];
  return (
    <div className="flex bg-panel border border-border rounded overflow-hidden shadow-sm" style={{ width: 200 }}>
      <Handle
        type="target"
        position={Position.Left}
        style={{ background: stripeColor, width: 6, height: 6, border: 0 }}
      />
      <div className="w-1" style={{ background: stripeColor }} />
      <div className="flex-1 px-2.5 py-2 min-w-0">
        <div className="text-[10px] text-muted2 font-mono truncate">{data.toolName}</div>
        <div className="text-xs text-text font-medium font-mono truncate mt-0.5">
          {data.stepId}
        </div>
        <div className="flex items-center gap-1 mt-1.5">
          <span
            className="w-1.5 h-1.5 rounded-full"
            style={{ background: stripeColor }}
          />
          <span className="text-[10px] font-medium" style={{ color: statusColor }}>
            {STATUS_LABEL[data.status]}
          </span>
          {data.durationMs !== null && (
            <span className="text-[10px] text-muted2 ml-1 font-mono">
              {data.durationMs}ms
            </span>
          )}
        </div>
      </div>
      <Handle
        type="source"
        position={Position.Right}
        style={{ background: stripeColor, width: 6, height: 6, border: 0 }}
      />
    </div>
  );
}

const NODE_TYPES: NodeTypes = { testudo: TestudoNode };

export function WorkflowGraph({ workflow, lastRun }: Props) {
  const nodes = useMemo<Node<TestudoNodeData>[]>(() => {
    if (!workflow) return [];
    const cols = Math.max(1, Math.ceil(Math.sqrt(workflow.steps.length)));
    return workflow.steps.map((step, i) => {
      const col = i % cols;
      const row = Math.floor(i / cols);
      const status = statusFor(step.id, lastRun, workflow.name);
      const durationMs = durationFor(step.id, lastRun, workflow.name);
      return {
        id: step.id,
        type: "testudo",
        data: {
          toolName: step.uses,
          stepId: step.id,
          status,
          durationMs,
        },
        position: { x: 30 + col * 240, y: 30 + row * 110 },
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
          style: { stroke: "#3a3a44", strokeWidth: 1.5 },
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
    <div className="relative w-full h-full">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={NODE_TYPES}
        fitView
        proOptions={{ hideAttribution: true }}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
      >
        <Background color="#3a3a44" />
        <Controls showInteractive={false} />
      </ReactFlow>
      {/* Floating brand inset top-right; pointer-events-none so DAG stays interactive */}
      <div
        className="pointer-events-none absolute top-3 right-3 z-10 bg-panel/80 backdrop-blur-sm border border-border rounded-md p-1.5 shadow-lg"
        aria-hidden="true"
      >
        <img
          src="./testudo-snap-inset.gif"
          alt=""
          width={72}
          height={60}
          style={{ imageRendering: "pixelated" }}
          className="block"
        />
      </div>
    </div>
  );
}
