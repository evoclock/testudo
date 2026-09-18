import { useCallback, useEffect, useState } from "react";
import {
  OPENAI_COMPATIBLE_PROVIDERS,
  seatsMethods,
  type BridgeClient,
  type OperationResponse,
  type SeatsConfig,
} from "../lib/api";

/**
 * Models & Seats settings panel (spec section 6 renderer surface).
 *
 * The renderer only echoes ids, revisions, and opaque challenges returned by
 * the bridge; it never supplies digests, commands, previews, or consent
 * state (R1). API keys are sent once to the bridge and never retained.
 */

interface Props {
  client: BridgeClient | null;
}

const WARNING_LINGER = "service may stop when this session ends";
const HOST_SIDE_INTERVENTION = "host-side intervention required";

export function SeatsPanel({ client }: Props) {
  const [config, setConfig] = useState<SeatsConfig | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [opResults, setOpResults] = useState<Record<string, OperationResponse>>({});
  const [keyStates, setKeyStates] = useState<Record<string, string>>({});
  const [keyDraft, setKeyDraft] = useState<{ provider: string; value: string } | null>(null);

  const refresh = useCallback(async () => {
    if (!client) return;
    setBusy(true);
    setError(null);
    try {
      const seats = seatsMethods(client);
      const next = await seats.seatsConfig();
      setConfig(next);
      const states: Record<string, string> = {};
      for (const provider of OPENAI_COMPATIBLE_PROVIDERS) {
        states[provider.id] = (await seats.seatsProviderKeyState(provider.id)).state;
      }
      setKeyStates(states);
    } catch (exc) {
      setError(String(exc));
    } finally {
      setBusy(false);
    }
  }, [client]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const addHost = useCallback(async () => {
    if (!client) return;
    const alias = window.prompt("SSH alias (as in ~/.ssh/config):");
    if (!alias) return;
    const seats = seatsMethods(client);
    try {
      const draft = await seats.seatsDraftCreate("host", {
        label: alias,
        ssh: { kind: "alias", alias },
        transport: { kind: "ssh-tunnel" },
      });
      const current = config?.revision ?? 0;
      await seats.seatsConfigApply(draft.draft_id, draft.draft_revision, current);
      await refresh();
    } catch (exc) {
      setError(String(exc));
    }
  }, [client, config, refresh]);

  const addSeat = useCallback(
    async (hostId: string) => {
      if (!client) return;
      const unit = window.prompt("systemd user unit name (e.g. model.service):");
      if (!unit) return;
      const modelId = window.prompt("Model id served on the endpoint:");
      if (!modelId) return;
      const port = Number(window.prompt("Endpoint port:", "8000") ?? "8000");
      const seats = seatsMethods(client);
      try {
        const draft = await seats.seatsDraftCreate(
          "seat",
          {
            label: unit,
            template: "systemd-user",
            unit,
            model_id: modelId,
            port,
            endpoint_host: "127.0.0.1",
            ready_timeout: 600,
          },
          hostId,
        );
        await seats.seatsConfigApply(
          draft.draft_id,
          draft.draft_revision,
          config?.revision ?? 0,
        );
        await refresh();
      } catch (exc) {
        setError(String(exc));
      }
    },
    [client, config, refresh],
  );

  const trustFlow = useCallback(
    async (hostId: string) => {
      if (!client) return;
      const seats = seatsMethods(client);
      try {
        const probe = await seats.seatsSshProbe(hostId, config?.revision ?? 0);
        const ok = window.confirm(
          `Verify this host key fingerprint out-of-band, then confirm:\n\n${probe.fingerprint}`,
        );
        if (!ok) return;
        await seats.seatsSshTrust(probe.trust_challenge_id);
        const preview = await seats.seatsPreview(hostId, (config?.revision ?? 0) + 1);
        const consented = window.confirm(
          `Consent preview (bridge-generated):\n\n${preview.text.slice(0, 2000)}`,
        );
        if (!consented) return;
        await seats.seatsConsentConfirm(preview.preview_id);
        await refresh();
      } catch (exc) {
        setError(String(exc));
      }
    },
    [client, config, refresh],
  );

  const operate = useCallback(
    async (seatId: string, operation: "start" | "stop" | "force-stop") => {
      if (!client) return;
      const seats = seatsMethods(client);
      try {
        let confirmationId: string | undefined;
        if (operation === "force-stop") {
          const challenge = await seats.seatsForceStopChallenge(seatId);
          const ok = window.confirm(
            "Force-stop sends SIGKILL to the seat. Confirm to use challenge " +
              challenge.confirmation_id,
          );
          if (!ok) return;
          confirmationId = challenge.confirmation_id;
        }
        const result = await seats.seatsOperate(seatId, operation, confirmationId);
        setOpResults((previous) => ({ ...previous, [seatId]: result }));
        await refresh();
      } catch (exc) {
        setError(String(exc));
      }
    },
    [client, refresh],
  );

  const saveKey = useCallback(async () => {
    if (!client || !keyDraft) return;
    const seats = seatsMethods(client);
    try {
      const result = await seats.seatsProviderKeyWrite(keyDraft.provider, keyDraft.value);
      setKeyStates((previous) => ({ ...previous, [keyDraft.provider]: result.state }));
      setKeyDraft(null);
    } catch (exc) {
      setError(String(exc));
    }
  }, [client, keyDraft]);

  if (!client) {
    return <div className="p-6 text-sm text-muted">Start the bridge to manage models and seats.</div>;
  }

  return (
    <div className="flex-1 overflow-auto p-6 space-y-6 text-sm">
      {error && (
        <div className="border border-red-500/40 bg-red-500/10 text-red-300 rounded p-3">
          {error}
        </div>
      )}

      <section>
        <h2 className="text-base font-semibold mb-2">Hosted providers</h2>
        <p className="text-muted mb-3">
          API keys are stored in the platform credential store; they are never
          written to files, logged, or shown again.
        </p>
        <div className="space-y-2">
          {OPENAI_COMPATIBLE_PROVIDERS.map((provider) => (
            <div key={provider.id} className="flex items-center gap-3 border border-border rounded p-3">
              <span className="font-medium">{provider.label}</span>
              <span className="text-muted">{provider.base_url}</span>
              <span
                className={
                  keyStates[provider.id] === "set"
                    ? "text-green-400"
                    : keyStates[provider.id] === "absent"
                      ? "text-muted"
                      : "text-amber-400"
                }
              >
                key: {keyStates[provider.id] ?? "…"}
              </span>
              <button
                type="button"
                className="ml-auto border border-border rounded px-3 py-1 hover:bg-bg"
                onClick={() => setKeyDraft({ provider: provider.id, value: "" })}
              >
                Set key
              </button>
            </div>
          ))}
        </div>
        {keyDraft && (
          <div className="mt-2 border border-border rounded p-3 space-y-2">
            <div className="font-medium">API key for {keyDraft.provider}</div>
            <input
              type="password"
              className="w-full bg-bg border border-border rounded px-2 py-1"
              value={keyDraft.value}
              onChange={(event) => setKeyDraft({ ...keyDraft, value: event.target.value })}
            />
            <div className="flex gap-2">
              <button type="button" className="border rounded px-3 py-1" onClick={() => void saveKey()}>
                Save to credential store
              </button>
              <button type="button" className="border rounded px-3 py-1" onClick={() => setKeyDraft(null)}>
                Cancel
              </button>
            </div>
          </div>
        )}
      </section>

      <section>
        <div className="flex items-center gap-3 mb-2">
          <h2 className="text-base font-semibold">SSH seats</h2>
          <button type="button" className="border border-border rounded px-3 py-1" onClick={() => void addHost()}>
            Add host
          </button>
          <button type="button" className="border border-border rounded px-3 py-1" onClick={() => void refresh()}>
            {busy ? "Refreshing…" : "Refresh"}
          </button>
        </div>
        <div className="space-y-4">
          {(config?.hosts ?? []).map((host) => (
            <div key={host.id} className="border border-border rounded p-4 space-y-3">
              <div className="flex items-center gap-3">
                <span className="font-medium">{host.label}</span>
                <span className="text-muted">
                  {host.ssh.kind === "alias" ? host.ssh.alias : `${host.ssh.user}@${host.ssh.host}:${host.ssh.port}`}
                </span>
                <span className="text-muted">{host.transport.kind}</span>
                <span className={host.consent ? "text-green-400" : "text-amber-400"}>
                  {host.consent ? "consented" : "consent required"}
                </span>
                {!host.consent && (
                  <button
                    type="button"
                    className="ml-auto border border-border rounded px-3 py-1"
                    onClick={() => void trustFlow(host.id)}
                  >
                    Trust &amp; consent
                  </button>
                )}
              </div>
              <div className="space-y-2">
                {host.seats.map((seat) => {
                  const result = opResults[seat.id];
                  return (
                    <div key={seat.id} className="flex items-center gap-3 border border-border/60 rounded px-3 py-2">
                      <span>{seat.label}</span>
                      <span className="text-muted">{seat.template}</span>
                      <span className="text-muted">
                        {seat.endpoint_host}:{seat.port}
                      </span>
                      <span className="text-muted">{seat.model_id}</span>
                      {result && (
                        <span
                          className={
                            result.state === "serving"
                              ? "text-green-400"
                              : result.state === "refused" || result.state === "error"
                                ? "text-red-400"
                                : "text-amber-400"
                          }
                        >
                          {result.state}
                          {result.error ? `: ${result.error}` : ""}
                        </span>
                      )}
                      <div className="ml-auto flex gap-2">
                        <button type="button" className="border rounded px-2 py-1" onClick={() => void operate(seat.id, "start")}>
                          Start
                        </button>
                        <button type="button" className="border rounded px-2 py-1" onClick={() => void operate(seat.id, "stop")}>
                          Stop
                        </button>
                        {seat.template !== "control-script" && (
                          <button
                            type="button"
                            className="border border-red-500/40 text-red-300 rounded px-2 py-1"
                            onClick={() => void operate(seat.id, "force-stop")}
                          >
                            Force-stop
                          </button>
                        )}
                      </div>
                      {result?.state === "refused" && result.error === "host lifetime prerequisite" && (
                        <div className="text-amber-400 w-full">{WARNING_LINGER}</div>
                      )}
                      {result?.state === "refused" && result.error === "unsupported: host-side intervention required" && (
                        <div className="text-amber-400 w-full">{HOST_SIDE_INTERVENTION}</div>
                      )}
                    </div>
                  );
                })}
                <button
                  type="button"
                  className="border border-border rounded px-3 py-1"
                  onClick={() => void addSeat(host.id)}
                >
                  Add seat
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
