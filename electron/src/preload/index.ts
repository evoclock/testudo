/**
 * Testudo preload script.
 *
 * The only seam between renderer (sandboxed, browser-context) and main
 * (Node, Electron). The renderer never imports `electron` or `node:*`;
 * it only sees the typed `window.testudo` API exposed via contextBridge.
 */
import { contextBridge, ipcRenderer } from "electron";

export interface BridgeStatus {
  running: boolean;
  url: string | null;
  token: string | null;
  port: number | null;
  pid: number | null;
  error: string | null;
}

export interface BridgeStartOptions {
  port?: number;
  host?: string;
  workflowsDir?: string;
  runsDir?: string;
}

export interface TestudoAPI {
  bridge: {
    status: () => Promise<BridgeStatus>;
    start: (opts?: BridgeStartOptions) => Promise<BridgeStatus>;
    stop: () => Promise<BridgeStatus>;
  };
  app: {
    quit: () => Promise<void>;
  };
  openFile: () => Promise<string | null>;
}

const api: TestudoAPI = {
  bridge: {
    status: () => ipcRenderer.invoke("bridge:status") as Promise<BridgeStatus>,
    start: (opts) => ipcRenderer.invoke("bridge:start", opts ?? {}) as Promise<BridgeStatus>,
    stop: () => ipcRenderer.invoke("bridge:stop") as Promise<BridgeStatus>,
  },
  app: {
    quit: () => ipcRenderer.invoke("app:quit") as Promise<void>,
  },
  openFile: () => ipcRenderer.invoke("testudo:openFile") as Promise<string | null>,
};

contextBridge.exposeInMainWorld("testudo", api);
