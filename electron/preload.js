// Testudo preload script.
//
// Bridges renderer (sandboxed) and main (Node) via a narrow API surface.
// Exposed APIs are added during the v0.1 sprint as IPC handlers in main.js stabilise.

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('testudo', {
  openFile: () => ipcRenderer.invoke('testudo:openFile'),
  runWorkflow: (args) => ipcRenderer.invoke('testudo:runWorkflow', args),
});
