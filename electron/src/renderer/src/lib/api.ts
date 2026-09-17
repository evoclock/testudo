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

export interface EnvCheck {
  ollama_url: string;
  ollama_running: boolean;
  ollama_models: string[];
  registry_providers?: RegistryProvider[];
  ollama_error: string | null;
  databricks_env_set: boolean;
  file_ops_extra_installed: boolean;
  databricks_extra_installed: boolean;
}

export class BridgeClient {
  constructor(public readonly url: string, private readonly token: string) {}

  headersForSeats(): Record<string, string> {
    return this.headers();
  }

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

  async envCheck(): Promise<EnvCheck> {
    const r = await fetch(`${this.url}/env-check`, { headers: this.headers() });
    if (!r.ok) throw new Error(`/env-check ${r.status}`);
    return (await r.json()) as EnvCheck;
  }

  async workflowReadme(name: string): Promise<string | null> {
    const r = await fetch(`${this.url}/workflows/${encodeURIComponent(name)}/readme`, {
      headers: this.headers(),
    });
    if (!r.ok) return null;
    const body = (await r.json()) as { name: string; readme: string | null };
    return body.readme;
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

export async function makeBridgeClient(): Promise<BridgeClient | null> {
  const status = await window.testudo.bridge.status();
  if (!status.running || !status.url || !status.token) return null;
  return new BridgeClient(status.url, status.token);
}


export interface RegistryModel {
  id: string;
  label: string;
  hint: string;
  reasoning: boolean;
}

export interface RegistryProvider {
  id: string;
  label: string;
  adapter: string;
  base_url: string;
  reachable: boolean | null;
  models: RegistryModel[];
}

// --- Seat control (Models & Seats settings panel) ---------------------------

export interface SeatHostSsh {
  kind: "alias" | "explicit";
  alias?: string;
  user?: string;
  host?: string;
  port?: number;
}

export interface SeatHostView {
  id: string;
  label: string;
  ssh: SeatHostSsh;
  transport: { kind: "trusted-lan" | "https" | "ssh-tunnel" };
  consent: { accepted_at: string } | null;
  seats: SeatView[];
}

export interface SeatView {
  id: string;
  label: string;
  template: "systemd-user" | "control-script" | "bare-command";
  model_id: string;
  port: number;
  endpoint_host: string;
  ready_timeout: number;
  unit?: string;
  script?: string;
  launch_argv?: string[];
  cwd?: string;
}

export interface SeatsConfig {
  schema: string;
  revision: number;
  hosts: SeatHostView[];
}

export interface DraftResponse {
  draft_id: string;
  draft_revision: number;
}

export interface ApplyResponse {
  id: string;
  config_revision: number;
}

export interface TrustChallengeResponse {
  trust_challenge_id: string;
  fingerprint: string;
  expires_at: number;
}

export interface PreviewResponse {
  preview_id: string;
  expires_at: number;
  text: string;
}

export interface OperationResponse {
  state: string;
  error: string | null;
  detail: string;
  occupant_models: string[];
}

export interface ProviderKeyState {
  provider_id: string;
  state: string;
}

export const OPENAI_COMPATIBLE_PROVIDERS = [
  { id: "openai", label: "OpenAI", base_url: "https://api.openai.com/v1" },
  { id: "openrouter", label: "OpenRouter", base_url: "https://openrouter.ai/api/v1" },
  {
    id: "merge-gateway",
    label: "merge-gateway",
    base_url: "https://api-gateway.merge.dev/v1/openai",
  },
] as const;

export interface SeatClientMethods {
  seatsConfig(): Promise<SeatsConfig>;
  seatsDraftCreate(kind: "host" | "seat", fields: Record<string, unknown>, parentHostId?: string): Promise<DraftResponse>;
  seatsDraftUpdate(draftId: string, draftRevision: number, patch: Record<string, unknown>): Promise<DraftResponse>;
  seatsConfigApply(draftId: string, draftRevision: number, expectedConfigRevision: number): Promise<ApplyResponse>;
  seatsConfigDelete(kind: "host" | "seat", id: string, expectedConfigRevision: number): Promise<{ config_revision: number }>;
  seatsSshProbe(hostId: string, expectedConfigRevision: number): Promise<TrustChallengeResponse>;
  seatsSshTrust(trustChallengeId: string): Promise<{ trusted: boolean; config_revision: number }>;
  seatsPreview(hostId: string, expectedConfigRevision: number): Promise<PreviewResponse>;
  seatsConsentConfirm(previewId: string): Promise<{ consented: boolean; config_revision: number }>;
  seatsOperate(seatId: string, operation: "start" | "stop" | "force-stop", confirmationId?: string): Promise<OperationResponse>;
  seatsForceStopChallenge(seatId: string): Promise<{ confirmation_id: string; expires_at: number }>;
  seatsProviderKeyWrite(providerId: string, key: string): Promise<ProviderKeyState>;
  seatsProviderKeyState(providerId: string): Promise<ProviderKeyState>;
}

export function seatsMethods(client: BridgeClient): SeatClientMethods {
  const post = async <T>(path: string, body: unknown): Promise<T> => {
    const r = await fetch(`${client.url}/seats/${path}`, {
      method: "POST",
      headers: client.headersForSeats(),
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      const detail = await r.text();
      throw new Error(`${path} ${r.status}: ${detail}`);
    }
    return (await r.json()) as T;
  };

  return {
    async seatsConfig() {
      const r = await fetch(`${client.url}/seats/config`, { headers: client.headersForSeats() });
      if (!r.ok) throw new Error(`/seats/config ${r.status}`);
      return (await r.json()) as SeatsConfig;
    },
    seatsDraftCreate: (kind, fields, parentHostId) =>
      post("draft", { kind, fields, parent_host_id: parentHostId }),
    seatsDraftUpdate: (draftId, draftRevision, patch) =>
      post("draft/update", { draft_id: draftId, draft_revision: draftRevision, patch }),
    seatsConfigApply: (draftId, draftRevision, expectedConfigRevision) =>
      post("config/apply", { draft_id: draftId, draft_revision: draftRevision, expected_config_revision: expectedConfigRevision }),
    seatsConfigDelete: (kind, id, expectedConfigRevision) =>
      post("config/delete", { kind, id, expected_config_revision: expectedConfigRevision }),
    seatsSshProbe: (hostId, expectedConfigRevision) =>
      post("ssh/probe", { host_id: hostId, expected_config_revision: expectedConfigRevision }),
    seatsSshTrust: (trustChallengeId) => post("ssh/trust", { trust_challenge_id: trustChallengeId }),
    seatsPreview: (hostId, expectedConfigRevision) =>
      post("preview", { host_id: hostId, expected_config_revision: expectedConfigRevision }),
    seatsConsentConfirm: (previewId) => post("consent", { preview_id: previewId }),
    seatsOperate: (seatId, operation, confirmationId) =>
      post("operate", { seat_id: seatId, operation, confirmation_id: confirmationId }),
    seatsForceStopChallenge: (seatId) => post("force-stop-challenge", { seat_id: seatId }),
    seatsProviderKeyWrite: (providerId, key) => post("provider-key", { provider_id: providerId, key }),
    seatsProviderKeyState: (providerId) => post("provider-key/state", { provider_id: providerId }),
  };
}
