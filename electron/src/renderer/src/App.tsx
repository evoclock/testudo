import { useEffect, useMemo, useState } from "react";
import { DatabasePanel } from "./components/DatabasePanel";
import { FilePanel } from "./components/FilePanel";
import { ModeTabs } from "./components/ModeTabs";
import { ResultLog, type LogEntry } from "./components/ResultLog";
import { UrlPanel } from "./components/UrlPanel";
import { WorkflowPanel } from "./components/WorkflowPanel";
import {
  type BridgeClient,
  type RunResponse,
  type WorkflowSummary,
  makeBridgeClient,
} from "./lib/api";
import { type Mode, buildRunRequest } from "./lib/modes";

export default function App() {
  const [client, setClient] = useState<BridgeClient | null>(null);
  const [version, setVersion] = useState<string>("");
  const [workflows, setWorkflows] = useState<WorkflowSummary[]>([]);
  const [bridgeStatus, setBridgeStatus] = useState<
    "connecting" | "online" | "offline"
  >("connecting");
  const [mode, setMode] = useState<Mode>("file");
  const [busy, setBusy] = useState(false);
  const [entries, setEntries] = useState<LogEntry[]>([
    {
      kind: "info",
      text:
        "Welcome. Pick a mode above (File, URL, Database, or Workflow), fill in the inputs, and hit Run. Findings and audit-log paths appear here.",
    },
  ]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const c = await makeBridgeClient();
        if (cancelled) return;
        setClient(c);
        const h = await c.health();
        const wf = await c.listWorkflows();
        if (cancelled) return;
        setVersion(h.version);
        setWorkflows(wf);
        setBridgeStatus("online");
      } catch (err) {
        if (cancelled) return;
        setBridgeStatus("offline");
        setEntries((e) => [
          ...e,
          {
            kind: "error",
            text: `Bridge unreachable: ${(err as Error).message}. Confirm testudo serve is running on the configured port and TESTUDO_BRIDGE_TOKEN is exported.`,
          },
        ]);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const knownWorkflowNames = useMemo(
    () => workflows.map((w) => w.name).join(", "),
    [workflows],
  );

  const submit = async (
    description: string,
    inputs: Record<string, unknown>,
    workflowPath: string,
    note?: string,
  ) => {
    if (!client) {
      setEntries((e) => [
        ...e,
        { kind: "error", text: "Bridge client not ready yet." },
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
    } catch (err) {
      setEntries((e) => [
        ...e,
        {
          kind: "error",
          text: `Run failed: ${(err as Error).message}`,
        },
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

  const renderPanel = () => {
    if (bridgeStatus === "offline") {
      return (
        <div className="flex flex-col items-center justify-center h-full text-center p-10 text-muted">
          <div className="text-lg mb-2">Bridge offline.</div>
          <div className="text-sm max-w-md">
            Start <code className="text-text">testudo serve --port 8000 --workflows-dir examples</code>{" "}
            in another terminal, export <code>TESTUDO_BRIDGE_TOKEN</code> with the
            token it prints, then restart this window.
          </div>
        </div>
      );
    }
    if (bridgeStatus === "connecting") {
      return (
        <div className="flex items-center justify-center h-full text-muted">
          Connecting to bridge...
        </div>
      );
    }
    switch (mode) {
      case "file":
        return (
          <FilePanel
            busy={busy}
            onRun={({ filePath, outputPath, note }) =>
              runMode({ filePath, outputPath }, `File: ${filePath}`, note || undefined)
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
        return <WorkflowPanel workflows={workflows} busy={busy} onRun={runWorkflow} />;
    }
  };

  return (
    <div className="grid grid-rows-[56px_1fr] h-full">
      <header className="bg-panel border-b border-border flex items-center px-5 gap-4">
        <div className="w-8 h-8 rounded bg-bg border border-border flex items-center justify-center text-xs text-muted">
          T
        </div>
        <div className="font-semibold tracking-wide">Testudo</div>
        <div className="text-xs text-muted">
          {bridgeStatus === "online" && `bridge v${version}`}
          {bridgeStatus === "connecting" && "connecting..."}
          {bridgeStatus === "offline" && "bridge offline"}
        </div>
        <div className="flex-1" />
        <div className="text-xs text-muted">
          {workflows.length} workflow{workflows.length === 1 ? "" : "s"}
        </div>
      </header>

      <div className="grid grid-cols-2 h-full overflow-hidden">
        <div className="flex flex-col h-full border-r border-border">
          <ModeTabs active={mode} onSelect={setMode} />
          <div className="flex-1 overflow-hidden">{renderPanel()}</div>
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
