# Compose smoke test (`compose-smoke-v015`)

A reference round-trip exercise for the **Compose** tab. The goal is to
prove the author -> save -> run cycle works end-to-end with zero
external dependencies (no network, no LLM, no database), so any failure
is in Testudo itself rather than in a flaky service.

The composition exercises four primitives from three modules
(`connectors`, `sanitisers`, `outputs`), drives the executor's
`${steps.x.y}` string interpolation across three references, and lands
output in both the Activity panel (chat channel) and on disk.

## What it does

```text
read_sample  ->  scan  ->  write_redacted  ->  respond
```

Linear chain. Each step depends only on the immediately previous one.

| Step id          | Tool                              | `with:` params                                                                                                                                                                                       |
|------------------|-----------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `read_sample`    | `connectors.local_file`           | `path = "~/testudo/examples/data/sample.md"`                                                                                                                                             |
| `scan`           | `sanitisers.pii_and_injection`    | `content = "${steps.read_sample.content}"`, `redact = true`                                                                                                                                          |
| `write_redacted` | `outputs.file`                    | `path = "~/testudo/outputs-ui/compose-smoke-redacted.md"`, `content = "${steps.scan.content}"`                                                                                           |
| `respond`        | `outputs.chat`                    | `text = "Compose smoke run finished. Critical: ${steps.scan.critical_count}, High: ${steps.scan.high_count}. Redacted file written."`, `attachments = []`                                            |

## Edges (`needs`)

- `scan` <- `read_sample`
- `write_redacted` <- `scan`
- `respond` <- `write_redacted`

The Compose canvas builds these as React Flow edges. Drag from the right
handle of a node to the left handle of the next.

## Walkthrough on the UI

1. Header -> **Start bridge**. Wait for the green `online :8000` badge.
2. Open the **Compose** tab.
3. In the top input, name the workflow `compose-smoke-v015`.
4. Description (optional): `synthetic round-trip: local file -> sanitiser -> file -> chat`.
5. From the left palette, click these four tools (in this order) to drop
   nodes onto the canvas:
   - `connectors.local_file`
   - `sanitisers.pii_and_injection`
   - `outputs.file`
   - `outputs.chat`
6. For each node, click it on the canvas. In the right-hand inspector:
   - Set the **Step id** to `read_sample` / `scan` / `write_redacted` / `respond` respectively.
   - Fill in the **With: params** table above. Strings go in verbatim;
     the `${steps...}` references are typed as literal text and resolved
     at run time by the executor.
7. Draw the three edges by dragging from each node's right handle to
   the next node's left handle: `read_sample -> scan -> write_redacted -> respond`.
8. Click **Save workflow**. The Activity panel logs
   `Workflow "compose-smoke-v015" saved.` and the bridge reloads its
   workflow list.
9. Switch to the **Workflow** tab. Pick `compose-smoke-v015` from the
   dropdown. The form has no inputs (Compose drafts ship with
   `inputs: {}`); the Note textarea is optional context for Activity.
10. Click **Run workflow**.

## Expected outcome

- Activity shows `compose-smoke-v015 completed` (green).
- The chat-channel block under the run reads something like
  `Compose smoke run finished. Critical: <N>, High: <M>. Redacted file written.`
  with `N` and `M` reflecting the PII fixtures currently in `sample.md`.
- The DAG panel turns all four step boxes green (`OK`).
- The redacted file lands at
  `~/testudo/outputs-ui/compose-smoke-redacted.md`.
- The audit-log path is rendered below the run badge; opening it shows
  one JSONL entry per step lifecycle event.

## Why this exact design

- **No external dependency.** Every step runs locally and
  deterministically. If the round-trip fails, the failure is in the
  authoring / save / run path, not in Ollama load, Databricks warehouse
  cold-start, or HTTPS flakiness.
- **Four distinct primitives.** Covers `connectors/`, `sanitisers/`,
  `outputs/`. Three modules from the six in the registry.
- **String interpolation under load.** Three `${steps.x.y}` references,
  two types (string content + integer counts inside the chat text).
  Proves the executor's `_resolve` path handles both exact-match
  ref-substitution and embedded-string interpolation.
- **Chat channel surfaced.** Validates that `outputs.chat` lands in the
  Activity panel via `ResultLog.extractChatBlock` and renders alongside
  any per-run note.
- **Linear, not parallel.** Keeps the DAG visually compact and the
  bug-bisection trivial if a step fails.

## Failure modes (so we don't chase ghosts)

| Symptom                                                   | Likely cause                                                                                                                            |
|-----------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| Save fails with `400 invalid workflow`                    | Step `id` collisions or a missing required param in `with:`. Re-check the inspector against the table above.                            |
| Run fails at `read_sample` with `FileNotFoundError`       | `examples/data/sample.md` not present. The path is in-tree; the file is committed.                                                      |
| Run fails at `scan` with `TypeError: expected string`     | The `content` ref didn't resolve. Verify the inspector shows literal `${steps.read_sample.content}` and not a stale paste.              |
| Run completes but chat block is empty                     | `respond` step's `text` field is empty. Re-open in the inspector and confirm the interpolation string is present.                       |
| Critical / High counts are both 0                         | `sample.md` was edited to remove its PII fixtures. Re-seed by checking out the file (`git checkout examples/data/sample.md`).           |

## After it passes

Once green end-to-end, the round-trip is proven and Testudo is at a
clean ship-point for v0.1.6: every UI mode (File / URL / Database /
Workflow / Compose) has been exercised on real artifacts. The
remaining v0.1.6 priority is wiring the Docker default execution path,
tracked in `NEXT_ACTIONS.md`.

## Related

- `electron/src/renderer/src/components/ComposePanel.tsx` -- the React
  Flow canvas + tool palette + save handler.
- `src/testudo/server/app.py` -- `POST /workflows` endpoint that
  Compose hits on Save.
- `examples/readmes/*.md` -- per-workflow READMEs that the Workflow
  tab fetches and renders as HTML.
