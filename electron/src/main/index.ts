/**
 * Testudo main process.
 *
 * Single BrowserWindow with a sandboxed renderer. The bridge token is
 * loaded from the TESTUDO_BRIDGE_TOKEN env var and forwarded to the
 * renderer via the preload script's contextBridge. The token never
 * appears in renderer-inspectable scope.
 */
import { app, BrowserWindow, dialog, ipcMain } from "electron";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let mainWindow: BrowserWindow | null = null;

const BRIDGE_URL = process.env.TESTUDO_BRIDGE_URL ?? "http://127.0.0.1:8000";
const BRIDGE_TOKEN = process.env.TESTUDO_BRIDGE_TOKEN ?? "";

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    title: "Testudo",
    backgroundColor: "#1f1f24",
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      preload: join(__dirname, "../preload/index.js"),
    },
  });

  if (process.env.ELECTRON_RENDERER_URL) {
    void mainWindow.loadURL(process.env.ELECTRON_RENDERER_URL);
  } else {
    void mainWindow.loadFile(join(__dirname, "../renderer/index.html"));
  }
}

app.whenReady().then(() => {
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

ipcMain.handle("testudo:bridgeConfig", () => ({
  url: BRIDGE_URL,
  token: BRIDGE_TOKEN,
}));

ipcMain.handle("testudo:openFile", async () => {
  if (!mainWindow) return null;
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ["openFile"],
    filters: [
      { name: "Text", extensions: ["txt", "md", "log", "csv", "tsv", "json"] },
      { name: "Documents", extensions: ["pdf", "docx", "pptx", "html", "htm"] },
      { name: "All", extensions: ["*"] },
    ],
  });
  return result.canceled ? null : result.filePaths[0];
});

ipcMain.handle(
  "testudo:spawnServe",
  (_event, args: { workflowsRoot: string; runsRoot: string }) => {
    const proc = spawn("testudo", [
      "serve",
      "--workflows-root",
      args.workflowsRoot,
      "--runs-root",
      args.runsRoot,
    ]);
    proc.stderr.setEncoding("utf-8");
    proc.stderr.on("data", (chunk: string) => {
      process.stderr.write(`[testudo serve] ${chunk}`);
    });
    proc.on("exit", (code) => {
      process.stderr.write(`[testudo serve] exited with ${code}\n`);
    });
    return { pid: proc.pid ?? -1 };
  },
);
