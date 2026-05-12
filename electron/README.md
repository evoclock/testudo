# Testudo Electron shell

TypeScript + React + electron-vite renderer. Wires to the testudo
FastAPI bridge via the preload `contextBridge`. The renderer never sees
Node or Electron globals; it only sees the typed `window.testudo` API
defined in `src/preload/index.ts`.

## Layout

- `src/main/` -- main process (Node + Electron). Spawns the FastAPI
  bridge, opens file dialogs, exposes the bridge URL and token via IPC.
- `src/preload/` -- contextBridge surface. The single seam between
  renderer and main.
- `src/renderer/` -- React 18 + Tailwind + React Flow. Sandboxed
  browser context.

## Build / run

The toolchain is electron-vite (Vite under the hood). One command:

```bash
npm install
npm run dev
```

`npm install` is a network fetch (intentionally not run during the
in-house bring-up). After install, `npm run dev` starts the renderer
on Vite's dev server and launches the Electron main process pointing
at it. `npm run build` produces a packaged `out/` dir.

## Bridge wiring

The main process reads `TESTUDO_BRIDGE_URL` and `TESTUDO_BRIDGE_TOKEN`
from its environment and forwards them to the renderer via
`window.testudo.getBridgeConfig()`. Defaults are `http://127.0.0.1:8765`
and `""` (empty token). Start the bridge with:

```bash
testudo serve
# prints the bearer token to stderr; export it as TESTUDO_BRIDGE_TOKEN
# before launching the Electron app for end-to-end auth.
```

## Type safety

Two tsconfigs (`tsconfig.node.json`, `tsconfig.web.json`) keep main /
preload (Node lib) separate from renderer (DOM lib). Run
`npm run typecheck` to validate both surfaces.
