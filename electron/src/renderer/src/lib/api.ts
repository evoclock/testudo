/**
 * Typed client for the Testudo FastAPI bridge.
 *
 * The bridge URL and bearer token come from the preload contextBridge,
 * never from renderer-side env vars. Construct one client per session.
 */

export interface WorkflowStepSummary {
  id: string;
  uses: string;
  needs: string[];
}

export interface WorkflowSummary {
  name: string;
  description: string | null;
  inputs: Record<string, unknown>;
  step_count: number;
  steps: WorkflowStepSummary[];
  path: string;
}

export interface RunRequestBody {
  workflow_path: string;
  inputs: Record<string, unknown>;
  run_id?: string;
}

export interface StepResultPayload {
  output: unknown;
  skipped: boolean;
  error: string | null;
}

export interface RunResponse {
  run_id: string;
  workflow_name: string;
  status: "completed" | "failed";
  results: Record<string, StepResultPayload>;
  audit_log: string;
}

export interface ToolParam {
  name: string;
  annotation: string;
  default: unknown;
  has_default: boolean;
  required: boolean;
}

export interface ToolSummary {
  name: string;
  module: string;
  doc: string | null;
  params: ToolParam[];
}

export interface WorkflowDraftStep {
  id: string;
  uses: string;
  needs: string[];
  with: Record<string, unknown>;
}

export interface WorkflowDraft {
  name: string;
  description?: string;
  inputs?: Record<string, unknown>;
  steps: WorkflowDraftStep[];
  permissions?: Record<string, unknown>;
  isolation?: Record<string, unknown>;
}

export interface WorkflowSaveResponse {
  name: string;
  path: string;
}

export class BridgeClient {
  constructor(private readonly url: string, private readonly token: string) {}

  private headers(): Record<string, string> {
    return {
      "Content-Type": "application/json",
      Authorization: `Bearer ${this.token}`,
    };
  }

  async health(): Promise<{ version: string }> {
    const r = await fetch(`${this.url}/health`);
    if (!r.ok) throw new Error(`/health ${r.status}`);
    return (await r.json()) as { version: string };
  }

  async listWorkflows(): Promise<WorkflowSummary[]> {
    const r = await fetch(`${this.url}/workflows`, { headers: this.headers() });
    if (!r.ok) throw new Error(`/workflows ${r.status}`);
    return (await r.json()) as WorkflowSummary[];
  }

  async listTools(): Promise<ToolSummary[]> {
    const r = await fetch(`${this.url}/tools`, { headers: this.headers() });
    if (!r.ok) throw new Error(`/tools ${r.status}`);
    return (await r.json()) as ToolSummary[];
  }

  async saveWorkflow(draft: WorkflowDraft): Promise<WorkflowSaveResponse> {
    const r = await fetch(`${this.url}/workflows`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(draft),
    });
    if (!r.ok) {
      const detail = await r.text();
      throw new Error(`/workflows ${r.status}: ${detail}`);
    }
    return (await r.json()) as WorkflowSaveResponse;
  }

  async createRun(body: RunRequestBody): Promise<RunResponse> {
    const r = await fetch(`${this.url}/runs`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(`/runs ${r.status}`);
    return (await r.json()) as RunResponse;
  }

  async getRun(runId: string): Promise<RunResponse> {
    const r = await fetch(`${this.url}/runs/${runId}`, { headers: this.headers() });
    if (!r.ok) throw new Error(`/runs/${runId} ${r.status}`);
    return (await r.json()) as RunResponse;
  }
}

export async function makeBridgeClient(): Promise<BridgeClient> {
  const config = await window.testudo.getBridgeConfig();
  return new BridgeClient(config.url, config.token);
}
