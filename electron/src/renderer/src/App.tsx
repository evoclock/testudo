import { useEffect, useState } from "react";
import { Chat, type Message } from "./components/Chat";
import { Sidebar } from "./components/Sidebar";
import { WorkflowGraph } from "./components/WorkflowGraph";
import {
  type BridgeClient,
  type RunResponse,
  type WorkflowSummary,
  makeBridgeClient,
} from "./lib/api";

export default function App() {
  const [client, setClient] = useState<BridgeClient | null>(null);
  const [version, setVersion] = useState<string>("");
  const [workflows, setWorkflows] = useState<WorkflowSummary[]>([]);
  const [selected, setSelected] = useState<WorkflowSummary | null>(null);
  const [attached, setAttached] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "system",
      text: "Welcome to Testudo. Pick a workflow on the left, attach a file if needed, and run.",
    },
  ]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const c = await makeBridgeClient();
      if (cancelled) return;
      setClient(c);
      try {
        const h = await c.health();
        const wf = await c.listWorkflows();
        if (cancelled) return;
        setVersion(h.version);
        setWorkflows(wf);
      } catch (err) {
        if (cancelled) return;
        setMessages((m) => [
          ...m,
          { role: "system", text: `Bridge unreachable: ${(err as Error).message}` },
        ]);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const handleSubmit = async (text: string): Promise<void> => {
    setMessages((m) => [...m, { role: "user", text }]);
    if (!client || !selected) {
      setMessages((m) => [
        ...m,
        { role: "system", text: "Select a workflow first; bridge not ready otherwise." },
      ]);
      return;
    }
    try {
      const inputs: Record<string, unknown> = { prompt: text };
      if (attached) inputs.transcript_path = attached;
      const run: RunResponse = await client.createRun({
        workflow_path: selected.path,
        inputs,
      });
      setMessages((m) => [
        ...m,
        {
          role: "system",
          text: `${run.workflow_name} ${run.status} (run ${run.run_id})`,
          meta: run,
        },
      ]);
    } catch (err) {
      setMessages((m) => [
        ...m,
        { role: "system", text: `Run failed: ${(err as Error).message}` },
      ]);
    }
  };

  const handleAttach = async (): Promise<void> => {
    const path = await window.testudo.openFile();
    if (path) setAttached(path);
  };

  return (
    <div className="grid grid-cols-[260px_1fr] grid-rows-[56px_1fr] h-full">
      <header className="col-span-2 bg-panel border-b border-border flex items-center px-5 font-semibold tracking-wide">
        Testudo
        <span className="ml-3 text-xs text-muted">{version && `bridge v${version}`}</span>
      </header>
      <Sidebar workflows={workflows} selected={selected} onSelect={setSelected} />
      <div className="grid grid-cols-2 h-full">
        <Chat
          messages={messages}
          attachedFile={attached}
          onSubmit={handleSubmit}
          onAttach={handleAttach}
        />
        <div className="border-l border-border h-full">
          <WorkflowGraph workflow={selected} />
        </div>
      </div>
    </div>
  );
}
