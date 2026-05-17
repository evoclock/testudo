---
title: "Packaging Testudo for distribution"
---

## Overview

Testudo ships as a clickable native app with no CLI prerequisites on the target machine.
The Python bridge (`testudo serve`) is compiled into a standalone binary by PyInstaller
and bundled inside the Electron app by electron-builder. The result is a `.dmg` on Mac
and an `AppImage` on Linux.

Builds are native: each platform must build on its own machine. Cross-compilation is
not supported.

| Build machine | Target | Output |
| --- | --- | --- |
| Mac mini M4 (arm64) | Corporate Mac M3 | `Testudo-*.dmg` |
| Linux workstation (x86-64) | Same machine | `Testudo-*.AppImage` |

## Prerequisites

### Mac mini M4

- Git, with SSH key authorised on `github.com:evoclock`
- [uv](https://github.com/astral-sh/uv) (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- Node.js 20+ and npm (`brew install node` or via nvm)
- No Python install needed beyond what uv manages

### Linux workstation

- Git
- uv (already present)
- Node.js 20+ and npm (already present)

## Build sequence — Mac (run on Mac mini M4)

### 1. Clone the private repo

```bash
git clone git@github.com:evoclock/testudo-dev.git testudo
cd testudo
```

### 2. Build the Python bridge binary

```bash
uv pip install -e ".[serve,dist]"
pyinstaller testudo.spec
```

This produces `dist/testudo-bridge` — a self-contained Mach-O binary (arm64). Verify
it runs before proceeding:

```bash
./dist/testudo-bridge serve --help
```

Expected: usage text for the `serve` subcommand. No Python interpreter needed at runtime.

### 3. Build the Electron app

```bash
cd electron
npm install
npm run pack:mac
```

`pack:mac` runs `electron-vite build` then `electron-builder --mac`. Output lands at:

- `../dist-electron/mac/Testudo.app` — unpacked app, runnable directly for smoke testing
- `../dist-electron/Testudo-<version>.dmg` — distributable disk image

## Build sequence — Linux (run on Linux workstation)

Same steps; swap the pack command:

```bash
git clone git@github.com:evoclock/testudo-dev.git testudo
cd testudo
uv pip install -e ".[serve,dist]"
pyinstaller testudo.spec
./dist/testudo-bridge serve --help   # verify binary

cd electron
npm install
npm run pack:linux
```

Output:

- `../dist-electron/linux-unpacked/testudo` — unpacked, runnable directly
- `../dist-electron/Testudo-<version>.AppImage` — distributable

## Smoke test (both platforms)

After `npm run pack:*` completes, test the unpacked build before distributing:

### Mac

```bash
open ../dist-electron/mac/Testudo.app
```

Wait for the Electron window. The bridge should start automatically and the UI should
reach the ready state within a few seconds. Open the Activity tab and confirm the bridge
status shows connected.

### Linux

```bash
../dist-electron/linux-unpacked/testudo
```

Same check: bridge starts, UI loads, Activity tab shows connected.

If the bridge does not start, check the Electron DevTools console
(`View > Toggle Developer Tools`) for the `[bridge]` log lines. The resolution order is:

1. `TESTUDO_CLI` env var (override)
2. `process.resourcesPath/testudo-bridge` (packaged binary — this path in a working build)
3. `.venv/bin/testudo` relative to repo root (dev mode only)
4. `testudo` on PATH (fallback)

A packaged build should always hit path 2. If it falls through to 3 or 4, the
`extraResources` copy did not run or the binary is not executable.

## Env file location in packaged installs

In a packaged app, the repo root does not exist on the target machine. Env files must be
placed in the platform userData directory instead:

| Platform | Path |
| --- | --- |
| Mac | `~/Library/Application Support/Testudo/` |
| Linux | `~/.config/Testudo/` |

Copy your filled-in env files there before first launch:

```bash
# Mac example
mkdir -p ~/Library/Application\ Support/Testudo
cp .env.ollama ~/Library/Application\ Support/Testudo/
cp .env.testudo ~/Library/Application\ Support/Testudo/
```

Minimum `.env.ollama` for an Ollama connection on the corporate Mac (assumes Ollama is
running on the Linux workstation with `OLLAMA_HOST=0.0.0.0`):

```text
OLLAMA_HOST=http://<linux-workstation-ip>:11434
```

See [OLLAMA_SETUP.md](OLLAMA_SETUP.md) for the full Ollama configuration guide.

## Distributing to the corporate Mac

1. Copy `Testudo-<version>.dmg` to the target machine (USB, AirDrop, or file share).
2. Open the DMG, drag `Testudo.app` to `/Applications`.
3. Place env files in `~/Library/Application Support/Testudo/` (see above).
4. Ensure Ollama is reachable from the corporate Mac before launching.
5. Double-click `Testudo.app`. No terminal interaction required.

## Updating an existing install

Pull the latest commits on the build machine, re-run the build sequence from step 2
(PyInstaller then electron-builder), and redistribute the new DMG or AppImage. The
userData env files on the target machine persist across updates.
