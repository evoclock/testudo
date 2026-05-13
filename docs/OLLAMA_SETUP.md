---
title: "Ollama setup for the models.ollama_chat tool"
---

The `models.ollama_chat` orchestrator tool calls an Ollama-served model
over HTTP and routes the response through `sanitise_output` before
returning it to the workflow. This document covers Ollama install,
pulling or signing in for a model, the `:cloud` suffix convention, and
pointing testudo at the daemon.

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
(or run as a systemd service on Linux: `systemctl --user enable --now ollama`).

## 2. The `:cloud` suffix convention

Ollama exposes two model classes through the same daemon:

- **Local models**: pulled to disk with `ollama pull <name>`. Name in the
  API call is e.g. `mistral:latest` or `magistral:latest`.
- **Cloud-served models**: hosted by Ollama, billed by Ollama, accessed
  through the daemon as a transparent proxy. Name in the API call ends
  in `:cloud`, e.g. `minimax-m2.7:cloud` or `gpt-oss:120b-cloud`. They
  do not occupy disk locally.

Sign in once with `ollama signin` to enable cloud-served models. From
then on the daemon handles auth and routing transparently; the only
difference visible to testudo is the model name string in the workflow's
`with.model` field.

## 3. Pull or sign in for the recommended models

Testudo's File mode picker shows ten recommended models grouped by
location. Pull the local ones, sign in once for the cloud ones; pick
whichever subset you'll actually use.

### Cloud-served (default group)

```bash
ollama signin   # one-time; enables every :cloud model below
```

| Model id (used in `with.model`)       | Hint |
|---------------------------------------|------|
| `minimax-m2.7:cloud`                  | **default**. long context, careful summaries |
| `mistral-large-3:675b-cloud`          | general-purpose, large |
| `qwen3-coder-next:cloud`              | code-leaning, large context |
| `gemini-3-flash-preview:cloud`        | fast general-purpose |
| `gpt-oss:120b-cloud`                  | open-source large |
| `devstral-2:123b-cloud`               | code-leaning large |

### Local (downloaded to disk)

```bash
ollama pull mistral
ollama pull magistral
ollama pull jan-code
ollama pull devstral-small-2:24b-instruct-2512-q4_K_M
```

| Model id                                           | Size | Hint |
|----------------------------------------------------|------|------|
| `mistral:latest`                                   | 7B   | general-purpose, runs locally |
| `magistral:latest`                                 | 23B  | reasoning model, runs locally |
| `jan-code:latest`                                  | 4B   | small / fast; short coding tasks |
| `devstral-small-2:24b-instruct-2512-q4_K_M`        | 24B  | code-leaning, q4 quant for VRAM headroom |

Any other model on the Ollama registry works too; the UI's picker has a
free-text field below the buttons for arbitrary names. List what is on
disk with:

```bash
ollama list
```

## 4. How the UI reflects what you have installed

The Electron app's header shows an `ollama up` / `ollama down` badge
once the bridge is online (sourced from `GET /env-check`, which probes
`TESTUDO_OLLAMA_URL`). Hovering over it shows the list of model tags
the daemon reports installed.

The File mode picker marks each recommended model with:

- a green `installed` chip if the daemon reports the tag (local pulls
  or cloud-served models you have signed in for);
- a grey `pull` chip otherwise, with the exact `ollama pull` or
  `ollama signin` command in a tooltip.

Cloud-served models appear under their canonical `<name>:cloud` tag
once the daemon recognises your sign-in.

## 5. Point testudo at Ollama

Default base URL is `http://localhost:11434`. Override with:

```bash
export TESTUDO_OLLAMA_URL=http://localhost:11434
```

For a remote Ollama (different machine), point at that host and make
sure your workflow's `permissions.network.egress` allow-list includes
the host:

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

When v0.1.6 lands the Docker default execution path, the per-workflow
`IsolationProfile` will enforce this allow-list at the container's
`iptables` layer rather than relying on host-side trust.

## 6. Use it from a workflow

Either run the bundled `workflow-pdf-summarise.json`:

```bash
testudo run examples/workflow-pdf-summarise.json --inputs-json <(echo '{
  "pdf_path": "examples/data/sample.md",
  "model": "minimax-m2.7:cloud",
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
    "model": "minimax-m2.7:cloud",
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

## 7. Use it from the Electron UI

File mode (`workflow-pdf-summarise-v015.json`) is the path of least
resistance: pick a document, optionally override the default model in
the picker, optionally add a Note for the activity log, hit **Run**.
The DAG panel shows `extract -> summarise -> write_summary -> respond`
with the custom node template (status stripe + tool name + step id +
duration) and colours nodes by step status once the run returns. The
chat-channel output of the `respond` step lands in the Activity panel
underneath the run's collapsed strip; click the strip to expand the
chat block + step list + audit-log path.

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
- Multi-provider adapters under the same `models.*` shape (Anthropic,
  OpenAI, Mistral, Google). All will share the sanitise-on-return
  invariant; only the auth + endpoint plumbing differs.

## Verifying a model end-to-end without testudo

If you want to sanity-check Ollama before bringing testudo into the loop:

```bash
curl http://localhost:11434/api/chat -d '{
  "model": "minimax-m2.7:cloud",
  "messages": [{"role": "user", "content": "Hello"}],
  "stream": false
}'
```

If you see a JSON response with a `message.content` field, the daemon
is healthy and testudo will be able to call it. If you get a
"connection refused", start `ollama serve`. If you get "model not
found", run `ollama pull <model>` (local) or `ollama signin` (cloud) first.
