// Testudo Electron shell - main process
//
// Purpose: launch a single BrowserWindow loading renderer/index.html. The
// renderer talks to the Testudo CLI via IPC handlers exposed below.
//
// v0.1 is intentionally minimal: a single window, no menu bar, no auto-update,
// no native modules. Subsequent versions will add menus, multi-window support,
// and tighter sandboxing.

const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1100,
    height: 750,
    title: 'Testudo',
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// ---------- IPC handlers (stubs; wired up properly during v0.1 sprint) ----------

ipcMain.handle('testudo:openFile', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile'],
  });
  return result.canceled ? null : result.filePaths[0];
});

ipcMain.handle('testudo:runWorkflow', async (_event, { workflowPath, inputs, prompt }) => {
  // v0.1: spawn `testudo run <workflowPath> --input <inputs>` and stream output back.
  // Stub returns a placeholder response so the renderer can wire the UI before the
  // CLI subcommand is implemented.
  return {
    status: 'not-implemented',
    message: 'testudo runWorkflow IPC handler is a stub for v0.1.',
    inputs,
    prompt,
    workflowPath,
  };
});
