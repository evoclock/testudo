import { useCallback, useEffect, useMemo, useState } from "react";
import { ComposePanel } from "./components/ComposePanel";
import { DatabasePanel } from "./components/DatabasePanel";
import { FilePanel } from "./components/FilePanel";
import { ModeTabs } from "./components/ModeTabs";
import { ResultLog, type LogEntry } from "./components/ResultLog";
import { UrlPanel } from "./components/UrlPanel";
import { WorkflowGraph } from "./components/WorkflowGraph";
import { WorkflowPanel } from "./components/WorkflowPanel";
import {
  BridgeClient,
  type EnvCheck,
  type RunResponse,
  type WorkflowSummary,
} from "./lib/api";
import { MODE_BINDINGS, type Mode, buildRunRequest } from "./lib/modes";

type BridgeUiState = "stopped" | "starting" | "online" | "stopping" | "error";

export default function App() {
  const [client, setClient] = useState<BridgeClient | null>(null);
  const [version, setVersion] = useState<string>("");
  const [workflows, setWorkflows] = useState<WorkflowSummary[]>([]);
  const [bridgeState, setBridgeState] = useState<BridgeUiState>("stopped");
  const [bridgeError, setBridgeError] = useState<string | null>(null);
  const [bridgePort, setBridgePort] = useState<number | null>(null);
  const [envCheck, setEnvCheck] = useState<EnvCheck | null>(null);
  const [mode, setMode] = useState<Mode>("file");
  const [busy, setBusy] = useState(false);
  const [entries, setEntries] = useState<LogEntry[]>([
    {
      kind: "info",
      text:
        'Welcome. Click "Start bridge" in the header to bring the FastAPI bridge up. Once it reports online, pick a mode (File / URL / Database / Workflow / Compose) and run.',
    },
  ]);

  const refreshWorkflows = useCallback(async (c: BridgeClient) => {
    const wf = await c.listWorkflows();
    setWorkflows(wf);
  }, []);

  const adoptStatus = useCallback(
    async (status: BridgeStatus) => {
      if (!status.running || !status.url || !status.token) {
        setClient(null);
        setBridgeState(status.error ? "error" : "stopped");
        setBridgeError(status.error);
        setBridgePort(null);
        return;
      }
      const c = new BridgeClient(status.url, status.token);
      setClient(c);
      setBridgePort(status.port);
      try {
        const h = await c.health();
        setVersion(h.version);
        await refreshWorkflows(c);
        try {
          setEnvCheck(await c.envCheck());
        } catch {
          setEnvCheck(null);
        }
        setBridgeState("online");
        setBridgeError(null);
      } catch (err) {
        setBridgeState("error");
        setBridgeError((err as Error).message);
      }
    },
    [refreshWorkflows],
  );

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const status = await window.testudo.bridge.status();
      if (!cancelled) await adoptStatus(status);
    })();
    return () => {
      cancelled = true;
    };
  }, [adoptStatus]);

  const startBridge = async () => {
    setBridgeState("starting");
    setBridgeError(null);
    setEntries((e) => [...e, { kind: "info", text: "Starting bridge..." }]);
    const status = await window.testudo.bridge.start();
    await adoptStatus(status);
    if (status.running) {
      setEntries((e) => [
        ...e,
        { kind: "system", text: `Bridge online on ${status.url}.` },
      ]);
    } else {
      setEntries((e) => [
        ...e,
        {
          kind: "error",
          text: `Bridge failed to start: ${status.error ?? "unknown error"}`,
        },
      ]);
    }
  };

  const stopBridge = async () => {
    setBridgeState("stopping");
    setEntries((e) => [...e, { kind: "info", text: "Stopping bridge..." }]);
    const status = await window.testudo.bridge.stop();
    await adoptStatus(status);
    setEnvCheck(null);
    setEntries((e) => [...e, { kind: "system", text: "Bridge stopped." }]);
  };

  const knownWorkflowNames = useMemo(
    () => workflows.map((w) => w.name).join(", "),
    [workflows],
  );

  const [selectedWorkflowName, setSelectedWorkflowName] = useState<string>("");
  const [lastRun, setLastRun] = useState<RunResponse | null>(null);

  const stagedWorkflow = useMemo<WorkflowSummary | null>(() => {
    if (mode === "workflow") {
      return workflows.find((w) => w.name === selectedWorkflowName) ?? null;
    }
    if (mode === "compose") {
      return null;
    }
    const binding = MODE_BINDINGS[mode];
    return workflows.find((w) => w.name === binding.workflowName) ?? null;
  }, [mode, selectedWorkflowName, workflows]);

  const submit = async (
    description: string,
    inputs: Record<string, unknown>,
    workflowPath: string,
    note?: string,
  ) => {
    if (!client) {
      setEntries((e) => [
        ...e,
        { kind: "error", text: "Bridge offline; click Start in the header first." },
      ]);
      return;
    }
    setEntries((e) => [...e, { kind: "user", text: description, note }]);
    setBusy(true);
    try {
      const run: RunResponse = await client.createRun({
        workflow_path: workflowPath,
        inputs,
      });
      setEntries((e) => [
        ...e,
        {
          kind: run.status === "completed" ? "system" : "error",
          text: `${run.workflow_name} ${run.status}.`,
          meta: run,
        },
      ]);
      setLastRun(run);
    } catch (err) {
      setEntries((e) => [
        ...e,
        { kind: "error", text: `Run failed: ${(err as Error).message}` },
      ]);
    } finally {
      setBusy(false);
    }
  };

  const runMode = (
    form: Record<string, unknown>,
    description: string,
    note?: string,
  ) => {
    const result = buildRunRequest(mode, workflows, form, null);
    if (!result.ok) {
      setEntries((e) => [
        ...e,
        {
          kind: "error",
          text: result.error,
          note: knownWorkflowNames
            ? `Bridge currently knows: ${knownWorkflowNames}`
            : undefined,
        },
      ]);
      return;
    }
    void submit(
      description,
      result.request.inputs,
      result.request.workflow_path,
      note,
    );
  };

  const runWorkflow = (
    workflow: WorkflowSummary,
    inputs: Record<string, unknown>,
  ) => {
    void submit(
      `Run "${workflow.name}" with ${Object.keys(inputs).length} inputs`,
      inputs,
      workflow.path,
    );
  };

  const onWorkflowSaved = useCallback(
    async (savedName: string, savedPath: string) => {
      setEntries((e) => [
        ...e,
        {
          kind: "system",
          text: `Workflow "${savedName}" saved.`,
          note: `Path: ${savedPath}. Switch to the Workflow tab to run it.`,
        },
      ]);
      if (client) {
        try {
          await refreshWorkflows(client);
        } catch (err) {
          setEntries((e) => [
            ...e,
            {
              kind: "error",
              text: `Could not refresh workflow list: ${(err as Error).message}`,
            },
          ]);
        }
      }
    },
    [client, refreshWorkflows],
  );

  const onComposeError = useCallback((message: string) => {
    setEntries((e) => [...e, { kind: "error", text: message }]);
  }, []);

  const renderPanel = () => {
    if (bridgeState !== "online") {
      const message =
        bridgeState === "starting"
          ? "Bridge starting..."
          : bridgeState === "stopping"
            ? "Bridge stopping..."
            : bridgeState === "error"
              ? `Bridge error: ${bridgeError}`
              : "Bridge stopped. Click Start in the header.";
      return (
        <div className="flex items-center justify-center h-full text-muted text-center p-8">
          {message}
        </div>
      );
    }
    switch (mode) {
      case "file":
        return (
          <FilePanel
            busy={busy}
            ollamaAvailable={envCheck?.ollama_running ?? false}
            installedModels={envCheck?.ollama_models ?? []}
            onRun={({ filePath, outputPath, model, note }) =>
              runMode(
                { filePath, outputPath, model },
                `File (${model}): ${filePath}`,
                note || undefined,
              )
            }
          />
        );
      case "url":
        return (
          <UrlPanel
            busy={busy}
            onRun={({ url, outputPath, maxBytes, note }) =>
              runMode({ url, outputPath, maxBytes }, `URL: ${url}`, note || undefined)
            }
          />
        );
      case "database":
        return (
          <DatabasePanel
            busy={busy}
            onRun={({ databasePath, query, outputPath, note }) =>
              runMode(
                { databasePath, query, outputPath },
                `Query against ${databasePath}: ${query.slice(0, 80)}${query.length > 80 ? "..." : ""}`,
                note || undefined,
              )
            }
          />
        );
      case "workflow":
        return (
          <WorkflowPanel
            workflows={workflows}
            busy={busy}
            onRun={runWorkflow}
            onSelectionChange={setSelectedWorkflowName}
          />
        );
      case "compose":
        return (
          <ComposePanel
            client={client}
            busy={busy}
            onSaved={onWorkflowSaved}
            onError={onComposeError}
          />
        );
    }
  };

  const headerStatusBadge = () => {
    const colour =
      bridgeState === "online"
        ? "bg-green-700 text-white"
        : bridgeState === "starting" || bridgeState === "stopping"
          ? "bg-yellow-600 text-black"
          : bridgeState === "error"
            ? "bg-red-700 text-white"
            : "bg-bg text-muted border border-border";
    const text =
      bridgeState === "online"
        ? `online ${bridgePort ? `:${bridgePort}` : ""}`
        : bridgeState;
    return <span className={`px-2 py-0.5 rounded text-[11px] ${colour}`}>{text}</span>;
  };

  return (
    <div className="grid grid-rows-[56px_1fr] h-full">
      <header className="bg-panel border-b border-border flex items-center px-5 gap-3">
        <img src="./logo.png" alt="Testudo" className="w-8 h-8 rounded object-cover" />
        <div className="font-semibold tracking-wide">Testudo</div>
        {headerStatusBadge()}
        {version && bridgeState === "online" && (
          <span className="text-xs text-muted">bridge v{version}</span>
        )}
        {envCheck && bridgeState === "online" && (
          <>
            <span
              title={
                envCheck.ollama_running
                  ? `Ollama up at ${envCheck.ollama_url}\nModels: ${envCheck.ollama_models.join(", ") || "(none pulled)"}`
                  : `Ollama offline at ${envCheck.ollama_url}\n${envCheck.ollama_error ?? "no error reported"}\nFile mode (LLM summarise) will fail until ollama serve is running.`
              }
              className={`px-2 py-0.5 rounded text-[11px] ${
                envCheck.ollama_running
                  ? "bg-green-700 text-white"
                  : "bg-amber-700 text-white"
              }`}
            >
              ollama {envCheck.ollama_running ? "up" : "down"}
            </span>
            <span
              title={
                envCheck.databricks_env_set
                  ? "DATABRICKS_SERVER_HOSTNAME / HTTP_PATH / TOKEN are exported"
                  : "DATABRICKS_* env vars not set; Database mode against Databricks will be unavailable"
              }
              className={`px-2 py-0.5 rounded text-[11px] ${
                envCheck.databricks_env_set
                  ? "bg-green-700 text-white"
                  : "bg-bg text-muted border border-border"
              }`}
            >
              databricks {envCheck.databricks_env_set ? "ready" : "n/a"}
            </span>
          </>
        )}
        <div className="flex-1" />
        {bridgeState === "online" && (
          <span className="text-xs text-muted">
            {workflows.length} workflow{workflows.length === 1 ? "" : "s"}
          </span>
        )}
        {bridgeState === "online" || bridgeState === "stopping" ? (
          <button
            type="button"
            onClick={stopBridge}
            disabled={bridgeState === "stopping"}
            className="px-3 py-1.5 rounded bg-bg border border-border text-sm hover:border-red-500/60 disabled:opacity-40"
          >
            Stop bridge
          </button>
        ) : (
          <button
            type="button"
            onClick={startBridge}
            disabled={bridgeState === "starting"}
            className="px-3 py-1.5 rounded bg-accent text-white text-sm font-medium disabled:opacity-40"
          >
            Start bridge
          </button>
        )}
      </header>

      <div className="grid grid-cols-2 h-full overflow-hidden">
        <div className="flex flex-col h-full border-r border-border">
          <ModeTabs active={mode} onSelect={setMode} />
          <div className="flex-1 overflow-hidden flex flex-col">
            <div className="flex-1 overflow-y-auto">{renderPanel()}</div>
            <div className="h-64 border-t border-border bg-bg/60">
              <div className="px-3 py-2 text-xs uppercase tracking-wider text-muted border-b border-border bg-panel flex items-center justify-between">
                <span>DAG</span>
                {stagedWorkflow && (
                  <span className="font-mono text-muted/80 normal-case">
                    {stagedWorkflow.name} · {stagedWorkflow.step_count} steps
                  </span>
                )}
              </div>
              <div className="h-[calc(100%-32px)]">
                <WorkflowGraph workflow={stagedWorkflow} lastRun={lastRun} />
              </div>
            </div>
          </div>
        </div>
        <div className="flex flex-col h-full bg-bg">
          <div className="px-5 py-3 border-b border-border bg-panel">
            <div className="text-xs uppercase tracking-wider text-muted">Activity</div>
          </div>
          <ResultLog entries={entries} />
        </div>
      </div>
    </div>
  );
}
