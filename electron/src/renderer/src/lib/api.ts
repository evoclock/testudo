/**
 * Typed client for the Testudo FastAPI bridge.
 *
 * The bridge URL and bearer token come from the preload contextBridge,
 * never from renderer-side env vars. Construct one client per session.
 */

export interface WorkflowSummary {
  name: string;
  description: string | null;
  inputs: Record<string, unknown>;
  step_count: number;
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
