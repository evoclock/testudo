/**
 * Testudo main process.
 *
 * Owns the FastAPI bridge subprocess via BridgeManager. The renderer
 * asks main to start / stop / inspect the bridge through IPC; the
 * token and URL never reach renderer scope except through the explicit
 * bridge:status return value, and they are scrubbed when the bridge
 * stops.
 */
import { app, BrowserWindow, dialog, ipcMain } from "electron";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { BridgeManager, type StartOptions } from "./bridge";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let mainWindow: BrowserWindow | null = null;
const bridge = new BridgeManager();

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
  bridge.killSync();
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  bridge.killSync();
});

ipcMain.handle("bridge:status", () => bridge.status());

ipcMain.handle("bridge:start", async (_event, opts: StartOptions = {}) => {
  try {
    return await bridge.start(opts);
  } catch (err) {
    return { ...bridge.status(), error: (err as Error).message };
  }
});

ipcMain.handle("bridge:stop", () => bridge.stop());

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
