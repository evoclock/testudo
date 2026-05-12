# Testudo Electron shell

TypeScript + React + electron-vite renderer. Wires to the testudo
FastAPI bridge via the preload `contextBridge`. The renderer never
sees Node or Electron globals; it only sees the typed `window.testudo`
API defined in `src/preload/index.ts`.

## Layout

- `src/main/` -- main process (Node + Electron). Reads the bridge
  URL + token from env, opens file dialogs, exposes them to the
  renderer via IPC.
- `src/preload/` -- contextBridge surface. The single seam between
  renderer and main.
- `src/renderer/` -- React 18 + Tailwind + React Flow. Sandboxed
  browser context.

## One-time setup

```bash
npm install
```

## Recommended run path (turnkey)

From the repo root, with the Python side already installed:

```bash
testudo ui
```

That command generates a fresh bearer token, starts the bridge in the
background, waits for `/health`, then spawns this app with the token
wired through. Ctrl-C tears down both processes.

## Manual run (for debugging the renderer in isolation)

```bash
# terminal 1 -- bridge
testudo serve --port 8000 --workflows-dir ../examples
# stderr: "[testudo] bearer token: <random-url-safe>"

# terminal 2 -- this renderer
export TESTUDO_BRIDGE_URL=http://127.0.0.1:8000
export TESTUDO_BRIDGE_TOKEN=<paste-the-token>
npm run dev
```

The main process reads `TESTUDO_BRIDGE_URL` (default
`http://127.0.0.1:8000`) and `TESTUDO_BRIDGE_TOKEN` (no default) from
its environment and forwards them to the renderer via
`window.testudo.getBridgeConfig()`.

## Scripts

```bash
npm run dev          # vite dev server + electron main
npm run build        # packaged out/ directory
npm run typecheck    # tsc --noEmit on both Node and DOM surfaces
```

## Type safety

Two tsconfigs (`tsconfig.node.json`, `tsconfig.web.json`) keep main +
preload (Node lib) separate from renderer (DOM lib). Run
`npm run typecheck` to validate both.
