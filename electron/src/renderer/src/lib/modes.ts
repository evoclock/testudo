/**
 * Mode model: each mode is bound to a canonical workflow, plus the form
 * fields the user fills in. The renderer keeps mode-state local; the API
 * client only sees an assembled RunRequestBody.
 */

import type { RunRequestBody, WorkflowSummary } from "./api";

export type Mode = "file" | "url" | "database" | "workflow";

export interface ModeBinding {
  workflowName: string;
  buildInputs: (form: Record<string, unknown>) => Record<string, unknown>;
}

export const MODE_BINDINGS: Record<Exclude<Mode, "workflow">, ModeBinding> = {
  file: {
    workflowName: "pdf-summarise-v015",
    buildInputs: (form) => ({
      pdf_path: form.filePath,
      model: form.model ?? "minimax-m2.5",
      system_prompt: form.systemPrompt ?? undefined,
      output_path: form.outputPath ?? "/tmp/testudo-file-summary.md",
    }),
  },
  url: {
    workflowName: "url-fetch-v015",
    buildInputs: (form) => ({
      url: form.url,
      output_path: form.outputPath ?? "/tmp/testudo-url-debrief.md",
      max_bytes: form.maxBytes ?? 10485760,
    }),
  },
  database: {
    workflowName: "db-query-v015",
    buildInputs: (form) => ({
      database_path: form.databasePath,
      query: form.query,
      parameters: form.parameters ?? [],
      output_path: form.outputPath ?? "/tmp/testudo-db-results.md",
    }),
  },
};

export type BuildResult =
  | { ok: true; request: RunRequestBody }
  | { ok: false; error: string };

export function buildRunRequest(
  mode: Mode,
  workflows: WorkflowSummary[],
  form: Record<string, unknown>,
  selectedWorkflow: WorkflowSummary | null,
): BuildResult {
  if (mode === "workflow") {
    if (!selectedWorkflow) return { ok: false, error: "select a workflow first" };
    return {
      ok: true,
      request: { workflow_path: selectedWorkflow.path, inputs: form },
    };
  }

  const binding = MODE_BINDINGS[mode];
  const wf = workflows.find((w) => w.name === binding.workflowName);
  if (!wf) {
    return {
      ok: false,
      error: `${binding.workflowName} is not in the bridge's workflows directory; start testudo serve with --workflows-dir pointing at examples/`,
    };
  }
  return {
    ok: true,
    request: { workflow_path: wf.path, inputs: binding.buildInputs(form) },
  };
}
