# Testudo Electron shell

Minimal Electron UI for Testudo: chat box, file-upload panel, output panel. Calls back into the Python CLI for actual workflow execution; the Electron process does no orchestration of its own.

## v0.1 surface

- Chat box: free-form prompt entry; submitted prompts trigger a workflow run.
- File upload: local file picker; uploaded file is staged into the workflow's `inputs/`.
- Output panel: renders the structured chat response from the workflow's last step plus a download link for any file outputs.

## Running locally (when v0.1 lands)

```bash
cd electron
npm install
npm start
```

The shell expects a `testudo` CLI on PATH and a Docker daemon reachable from the host.
