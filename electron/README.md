# Testudo Electron shell

TypeScript + React + electron-vite renderer. Owns the FastAPI bridge
subprocess lifecycle: a Start / Stop button in the header spawns and
kills the bridge from inside the app. Closing the window cleans up
automatically.

## Layout

- `src/main/`
  - `index.ts` -- BrowserWindow + IPC handlers.
  - `bridge.ts` -- `BridgeManager` class that owns the `testudo serve`
    subprocess. Token + URL live here; the renderer only sees them
    via `bridge:status` IPC return values.
- `src/preload/` -- contextBridge surface. Exposes `window.testudo`
  with `bridge.{status, start, stop}` and `openFile`.
- `src/renderer/` -- React 18 + Tailwind + React Flow. Sandboxed
  browser context.

## One-time setup

```bash
npm install
```

You also need the Python side installed (run from the repo root):

```bash
uv pip install -e ".[serve]"
```

## Run

```bash
npm run dev
```

The Electron window opens with the bridge **stopped**. Click **Start
bridge** in the header. The main process:

1. Resolves the `testudo` binary (looks for `<repo>/.venv/bin/testudo`,
   then PATH).
2. Spawns it as `testudo serve --port 8000 --workflows-dir <repo>/examples`.
3. Captures the bearer-token line from its stderr.
4. Polls `/health` until the bridge responds.
5. Reports `{running, url, token, port}` to the renderer via the
   `bridge:status` IPC channel.

The renderer builds its FastAPI client against those values. Close
the window or click **Stop bridge** to tear the subprocess down.

## Scripts

```bash
npm run dev          # vite dev server + electron main
npm run build        # packaged out/ directory
npm run typecheck    # tsc --noEmit on Node and DOM surfaces
```

## Two-terminal flow (debugging only)

If you want to inspect the renderer against a bridge running in a
separate process (e.g. to attach a debugger to uvicorn):

```bash
# terminal 1
testudo serve --port 8000 --workflows-dir ../examples

# terminal 2 (env vars short-circuit the in-app Start button)
export TESTUDO_BRIDGE_URL=http://127.0.0.1:8000
export TESTUDO_BRIDGE_TOKEN=<paste-the-token>
npm run dev
```

When the env vars are set the renderer adopts the existing bridge
on launch instead of starting one itself.

## Type safety

Two tsconfigs:

- `tsconfig.node.json` -- main + preload (Node lib).
- `tsconfig.web.json` -- renderer (DOM lib).

`npm run typecheck` runs both.
