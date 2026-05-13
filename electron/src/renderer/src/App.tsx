import { useCallback, useEffect, useMemo, useState } from "react";
import { Group, Panel, Separator } from "react-resizable-panels";
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

    // Safety net: if the IPC promise hasn't resolved in 35s, force the UI
    // out of "starting" so the user is never stranded on the yellow badge.
    const safetyTimer = window.setTimeout(() => {
      setBridgeState((current) => (current === "starting" ? "error" : current));
      setBridgeError("bridge.start did not resolve within 35s; check the main-process terminal for stderr from `testudo serve`");
      setEntries((e) => [
        ...e,
        {
          kind: "error",
          text:
            "Bridge.start did not resolve within 35s. Look at the terminal where you ran `npm run dev` -- the main process logs `[testudo serve] ...` stderr lines that explain why.",
        },
      ]);
    }, 35_000);

    try {
      const status = await window.testudo.bridge.start();
      window.clearTimeout(safetyTimer);
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
    } catch (err) {
      window.clearTimeout(safetyTimer);
      setBridgeState("error");
      setBridgeError((err as Error).message);
      setEntries((e) => [
        ...e,
        { kind: "error", text: `Bridge IPC threw: ${(err as Error).message}` },
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
    note?: string,
  ) => {
    void submit(
      `Run "${workflow.name}" with ${Object.keys(inputs).length} inputs`,
      inputs,
      workflow.path,
      note,
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
      const isStarting = bridgeState === "starting";
      const isStopping = bridgeState === "stopping";
      const isError = bridgeState === "error";
      const message = isStarting
        ? "Bridge starting..."
        : isStopping
          ? "Bridge stopping..."
          : isError
            ? `Bridge error: ${bridgeError}`
            : "Bridge stopped";
      const dotColour = isStarting || isStopping
        ? "bg-amber-500 animate-pulse"
        : isError
          ? "bg-red-500"
          : "bg-muted2";

      return (
        <div className="flex flex-col h-full p-5 gap-4">
          {/* Faint outlines of panels-to-come */}
          <div className="opacity-25 space-y-3 pointer-events-none">
            <div className="h-9 border border-dashed border-border rounded" />
            <div className="space-y-2">
              <div className="h-3 w-24 border border-dashed border-border rounded" />
              <div className="h-9 border border-dashed border-border rounded" />
            </div>
            <div className="space-y-2">
              <div className="h-3 w-24 border border-dashed border-border rounded" />
              <div className="h-20 border border-dashed border-border rounded" />
            </div>
          </div>
          {/* Centred CTA card */}
          <div className="flex-1 flex items-center justify-center">
            <div className="bg-panel border border-border rounded-lg p-6 max-w-sm text-center shadow-lg">
              <div className="flex items-center justify-center gap-2 mb-3">
                <span className={`w-2 h-2 rounded-full ${dotColour}`} />
                <span className="text-[11px] uppercase tracking-[0.12em] text-muted2 font-semibold">
                  {message}
                </span>
              </div>
              {!isError && !isStarting && !isStopping && (
                <>
                  <p className="text-sm text-text mb-1">
                    Welcome to Testudo
                  </p>
                  <p className="text-xs text-muted leading-relaxed mb-4">
                    Click <span className="text-text font-medium">Start bridge</span> in the
                    header to bring the FastAPI bridge online. Once connected, pick a mode
                    (File / URL / Database / Workflow / Compose) to load a workflow.
                  </p>
                  <button
                    type="button"
                    onClick={startBridge}
                    className="px-4 py-2 rounded bg-accent text-white text-sm font-medium hover:bg-accent/90"
                  >
                    Start bridge
                  </button>
                </>
              )}
              {isError && (
                <>
                  <p className="text-sm text-text mb-1">Bridge failed to start</p>
                  <p className="text-xs text-muted leading-relaxed">
                    {bridgeError}
                  </p>
                </>
              )}
            </div>
          </div>
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
            databricksReady={envCheck?.databricks_env_set ?? false}
            onRun={({ adapter, databasePath, query, outputPath, note }) =>
              runMode(
                { adapter, databasePath, query, outputPath },
                `${adapter === "databricks" ? "Databricks" : `DuckDB(${databasePath})`}: ${query.slice(0, 80)}${query.length > 80 ? "..." : ""}`,
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
            client={client}
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
    <div className="flex flex-col h-full">
      <header className="bg-panel border-b border-border shrink-0">
        {/* Top row: wordmark + bridge status + version + workflows + actions */}
        <div className="flex items-center px-5 h-14 gap-3">
          <img
            src="./testudo-wordmark.png"
            alt="Testudo"
            className="h-9 w-auto"
            style={{ imageRendering: "auto" }}
          />
          {headerStatusBadge()}
          {version && bridgeState === "online" && (
            <span className="text-xs text-muted font-mono">v{version}</span>
          )}
          <div className="flex-1" />
          {bridgeState === "online" && (
            <span className="text-xs text-muted font-mono">
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
          <button
            type="button"
            onClick={() => {
              void window.testudo.app.quit();
            }}
            title="Stop the bridge (if running) and exit Testudo"
            className="px-3 py-1.5 rounded bg-bg border border-border text-sm hover:border-red-500/60 hover:text-red-300"
          >
            Quit
          </button>
        </div>

        {/* Bottom tier: env-check strip with breathing room */}
        <div className="flex items-center px-5 h-8 gap-3 border-t border-border/50 bg-panel2/40">
          <span className="text-[10px] uppercase tracking-[0.14em] text-muted2">
            Environment
          </span>
          {envCheck && bridgeState === "online" ? (
            <>
              <span
                title={
                  envCheck.ollama_running
                    ? `Ollama up at ${envCheck.ollama_url}\nModels: ${envCheck.ollama_models.join(", ") || "(none pulled)"}`
                    : `Ollama offline at ${envCheck.ollama_url}\n${envCheck.ollama_error ?? "no error reported"}\nFile mode (LLM summarise) will fail until ollama serve is running.`
                }
                className="flex items-center gap-1.5 text-[11px]"
              >
                <span
                  className={`w-1.5 h-1.5 rounded-full ${
                    envCheck.ollama_running ? "bg-green-500" : "bg-amber-500"
                  }`}
                />
                <span className="text-muted">ollama</span>
                <span className="text-text">
                  {envCheck.ollama_running ? "up" : "down"}
                </span>
                {envCheck.ollama_running && envCheck.ollama_models.length > 0 && (
                  <>
                    <span className="text-muted2">·</span>
                    <span className="text-muted2 font-mono">
                      {envCheck.ollama_models.length} model
                      {envCheck.ollama_models.length === 1 ? "" : "s"}
                    </span>
                  </>
                )}
              </span>
              <span
                title={
                  envCheck.databricks_env_set
                    ? "DATABRICKS_SERVER_HOSTNAME / HTTP_PATH / TOKEN are exported"
                    : "DATABRICKS_* env vars not set; Database mode against Databricks will be unavailable"
                }
                className="flex items-center gap-1.5 text-[11px]"
              >
                <span
                  className={`w-1.5 h-1.5 rounded-full ${
                    envCheck.databricks_env_set ? "bg-green-500" : "bg-muted2"
                  }`}
                />
                <span className="text-muted">databricks</span>
                <span className={envCheck.databricks_env_set ? "text-text" : "text-muted2"}>
                  {envCheck.databricks_env_set ? "ready" : "n/a"}
                </span>
              </span>
            </>
          ) : (
            <span className="text-[11px] text-muted2">
              {bridgeState === "online" ? "checking environment..." : "bridge offline"}
            </span>
          )}
        </div>
      </header>

      <Group orientation="horizontal" className="flex-1 overflow-hidden">
        <Panel defaultSize={"50%"} minSize={"25%"} className="flex flex-col overflow-hidden">
          <ModeTabs active={mode} onSelect={setMode} />
          <div className="flex-1 overflow-y-auto">{renderPanel()}</div>
        </Panel>
        <Separator className="w-1 bg-border hover:bg-accent transition-colors" />
        <Panel defaultSize={"50%"} minSize={"25%"}>
          <Group orientation="vertical" className="h-full bg-bg">
            <Panel defaultSize={"60%"} minSize={"20%"} className="flex flex-col overflow-hidden">
              <div className="px-5 py-3 border-b border-border bg-panel flex items-center justify-between">
                <div className="text-xs uppercase tracking-wider text-muted">DAG</div>
                {stagedWorkflow && (
                  <div className="font-mono text-[11px] text-muted/80">
                    {stagedWorkflow.name} · {stagedWorkflow.step_count} steps
                  </div>
                )}
              </div>
              <div className="flex-1">
                <WorkflowGraph workflow={stagedWorkflow} lastRun={lastRun} />
              </div>
            </Panel>
            <Separator className="h-1 bg-border hover:bg-accent transition-colors" />
            <Panel defaultSize={"40%"} minSize={"15%"} className="flex flex-col overflow-hidden">
              <div className="px-5 py-3 border-b border-border bg-panel">
                <div className="text-xs uppercase tracking-wider text-muted">Activity</div>
              </div>
              <ResultLog entries={entries} />
            </Panel>
          </Group>
        </Panel>
      </Group>
    </div>
  );
}
