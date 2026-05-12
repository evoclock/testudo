/**
 * Testudo preload script.
 *
 * The only seam between renderer (sandboxed, browser-context) and main
 * (Node, Electron). The renderer never imports `electron` or `node:*`;
 * it only sees the typed API exposed via contextBridge here.
 */
import { contextBridge, ipcRenderer } from "electron";

export interface BridgeConfig {
  url: string;
  token: string;
}

export interface TestudoAPI {
  getBridgeConfig: () => Promise<BridgeConfig>;
  openFile: () => Promise<string | null>;
  spawnServe: (args: { workflowsRoot: string; runsRoot: string }) => Promise<{ pid: number }>;
}

const api: TestudoAPI = {
  getBridgeConfig: () => ipcRenderer.invoke("testudo:bridgeConfig") as Promise<BridgeConfig>,
  openFile: () => ipcRenderer.invoke("testudo:openFile") as Promise<string | null>,
  spawnServe: (args) =>
    ipcRenderer.invoke("testudo:spawnServe", args) as Promise<{ pid: number }>,
};

contextBridge.exposeInMainWorld("testudo", api);
