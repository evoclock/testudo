---
title: "Ollama setup for the models.ollama_chat tool"
---

The `models.ollama_chat` orchestrator tool calls an Ollama-served model
over HTTP and routes the response through `sanitise_output` before
returning it to the workflow. This document covers Ollama install,
pulling a model (defaults to `minimax-m2.5`), and pointing testudo at
the daemon.

## 1. Install Ollama

Linux:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

macOS:

```bash
brew install ollama
# or download the .app from https://ollama.com/download/mac
```

Verify:

```bash
ollama --version
ollama serve   # starts the daemon on http://localhost:11434
```

The daemon listens on `127.0.0.1:11434` by default. Leave it running
(or run as a systemd service on Linux; `systemctl --user enable --now ollama`).

## 2. Pull the recommended models

Testudo's File mode surfaces four models in the picker. Pull whichever
you intend to use:

```bash
ollama pull mistral          # general-purpose default in the UI
ollama pull minimax-m2.5     # long-context, careful summaries
ollama pull jan-code-4b      # small / fast; good for code-heavy tasks
ollama pull chandra-ocr-2    # OCR over scanned documents
```

Any other model on the Ollama registry works too; pass its name as the
`model` input to the workflow. The UI's picker has a free-text field
under the four buttons for that case.

List what is on disk:

```bash
ollama list
```

The Electron app's header shows an `ollama up` / `ollama down` badge
once the bridge is online. Hovering over it shows the list of models
the daemon reports installed; the File mode picker marks each
recommended model with `installed` (green) or `pull` (grey) so you
can tell which ones still need `ollama pull`.

## 3. Point testudo at Ollama

Default base URL is `http://localhost:11434`. Override with:

```bash
export TESTUDO_OLLAMA_URL=http://localhost:11434
```

For a remote Ollama (different machine), point at that host's address
and make sure your workflow's `permissions.network.egress` allow-list
includes the host:

```bash
export TESTUDO_OLLAMA_URL=http://ollama.internal:11434
```

The workflow JSON:

```json
{
  "permissions": {
    "network": {"egress": ["ollama.internal"]}
  }
}
```

## 4. Use it from a workflow

Either run the bundled `workflow-pdf-summarise.json`:

```bash
testudo run examples/workflow-pdf-summarise.json --inputs-json <(echo '{
  "pdf_path": "examples/data/sample.md",
  "model": "minimax-m2.5",
  "output_path": "runs/sample-summary.md"
}')
```

Or compose your own step in any workflow:

```json
{
  "id": "summarise",
  "uses": "models.ollama_chat",
  "needs": ["extract"],
  "with": {
    "model": "minimax-m2.5",
    "system": "You are a careful, factual summariser.",
    "prompt": "Summarise: ${steps.extract.content}",
    "temperature": 0.0
  }
}
```

The tool's output shape:

```text
{
  "model": "<the model name>",
  "decision": "accept" | "redact" | "reject",
  "content": "<sanitised text>",
  "raw_length": <chars before sanitisation>,
  "sanitised_length": <chars after>,
  "findings": [...]
}
```

`content` is what `${steps.summarise.content}` resolves to in later
steps. Downstream tools therefore never see the raw model output, only
the sanitised version. If the model emits PII, secrets, hidden unicode,
prompt-injection markers, or OWASP / MCP threat patterns, they are
caught at this boundary.

## 5. Use it from the Electron UI

File mode (`workflow-pdf-summarise.json`) is the path of least
resistance: pick a document, optionally override the default model, hit
**Run**. The DAG panel below the form shows `extract -> summarise ->
write_summary -> respond` and colours nodes by step status once the run
returns.

## What's deferred to v0.2

- Streaming responses (`stream: true`). v0.1.5 always sets
  `stream: false` so the orchestrator gets one complete response per
  call. Streaming would let the UI render tokens as they arrive but
  needs a websocket on the bridge.
- The `/api/generate` endpoint (single-turn, no system / multi-message
  context). v0.1.5 always uses `/api/chat`. If a deployed Ollama only
  exposes `/api/generate` we'll add a fallback.
- Multi-turn chat threads. The current tool sends one user message
  per call. Multi-turn would require an orchestrator-level conversation
  store, which is out of scope until the orchestrator has async +
  parallel step support.

## Verifying a model end-to-end without testudo

If you want to sanity-check Ollama before bringing testudo into the loop:

```bash
curl http://localhost:11434/api/chat -d '{
  "model": "minimax-m2.5",
  "messages": [{"role": "user", "content": "Hello"}],
  "stream": false
}'
```

If you see a JSON response with a `message.content` field, the daemon
is healthy and testudo will be able to call it. If you get a
"connection refused", start `ollama serve`. If you get "model not
found", run `ollama pull <model>` first.
