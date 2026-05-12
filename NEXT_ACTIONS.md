# Testudo next actions

Companion to `STATUS.md`. Lists what the next session should pick up,
in priority order, with the user's current intent attached.

## Priority 0 -- user-side setup (unblocks several deferred items)

These need user input or external accounts; they are the only items
intentionally deferred.

- **Databricks live integration test.** User: "I will set up something in
  Databricks later". Once a workspace is provisioned, expose
  `DATABRICKS_HTTP_PATH`, `DATABRICKS_SERVER_HOSTNAME`,
  `DATABRICKS_TOKEN` as env, then re-enable the
  `tests/test_data_databricks.py` integration test (currently mocked).
- **aikido intel API token** (`https://intel.aikido.dev/`, marked
  important). Once a token is provisioned, scaffold an `[aikido]` extra
  with a thin client; merge findings into the existing `Finding`
  envelope.
- **Opengrep / Semgrep CI.** Author a rule pack against `src/testudo/`,
  commit `.github/workflows/semgrep.yml`. Local install needs network
  but is otherwise frictionless.

## Priority 1 -- finish in-house items (no external deps)

- **Wire the read-only -> sanitiser -> write-only MCP chain into the
  orchestrator.** Today the three servers exist as standalone STDIO
  scripts. The orchestrator should default to spawning the trio for any
  workflow step that touches LLM output going to disk. Audit-log the
  receipt id alongside `step_end`.
- **Expose `RateLimitMiddleware` config via `testudo serve` flags.**
  Currently the limiter is constructed with default capacity and
  refill. CLI flags: `--rate-capacity`, `--rate-refill-per-sec`.
- **Audit-log integration for the scan-then-permit gate.** When
  `ScanRejected` fires, emit a `permission_denied` audit event with
  `operation="scan.rejected"` and the worst-finding label.
- **Default-on the scan-before-permit gate** at orchestrator-level
  call sites that currently use `require_filesystem_read` /
  `require_filesystem_write`. Flag-gate so v0.1.5 callers still work.
- **Integration test: chain capturer -> sanitiser -> writer.** Today
  the components are tested in isolation; one end-to-end test would
  cover the receipt round-trip.

## Priority 2 -- Presidio NLP layer (in-house first; Presidio supplemental)

Per user 2026-05-12: in-house first; third-party tools are supplemental
options. The in-house regex stack is primary. Presidio is the planned
v0.2 supplemental for higher recall on names / places / organisations.

- Sketch is in `src/testudo/sanitisers/pii.py` docstring (v0.2 plan
  section). Code path: install `presidio-analyzer` + `presidio-anonymizer`
  + `spacy`; download `en_core_web_lg` (~750 MB).
- Hybrid pipeline: regex findings (high precision) + Presidio findings
  (higher recall) + confidence-merged result. Per Protecto's "Why
  Regex Fails for PII Detection in Unstructured Text".
- Behind a `[sanitisers]` extra so the runtime stays light.

## Priority 3 -- renderer polish

The TS / React renderer is up, the bridge lifecycle is in-app
(BridgeManager + Start/Stop button), env-check tells the user when
Ollama is reachable. Next:

- Add a Vitest + Playwright smoke test (mocks `window.testudo` and
  drives the five tabs).
- Live run progress: stream step status as the orchestrator runs
  (today we colour nodes post-run only).
- Surface env-check findings inline in the offending mode (e.g. File
  mode should hard-fail with a Start-Ollama hint when ollama_running
  is false, rather than letting the run start and the LLM call
  return a 500).
- Packaged installer: `electron-builder` build that produces a
  .AppImage / .dmg / .exe so end users can double-click to launch
  instead of `npm run dev`.

## Priority 4 -- v0.2 deferred (carry forward)

From `CHANGELOG.md` "Deferred to v0.2":

- File-format exploit detection (PDF JS objects, Office macros, archive
  zip-slip beyond the existing path-traversal patterns).
- Schema validation and regression diff for structured outputs.
- Async / parallel step execution in the orchestrator.
- Network egress allow-list enforcement at the Docker layer.

## Done this sprint (do not re-do)

See `STATUS.md` "Sprint scope (delivered this session)" for the
exhaustive list. Highlights:

- Hillstar redaction parity (16 missing patterns ported).
- ~50 country-specific PII patterns.
- Hidden-unicode + comment payloads + ANTHROPIC_BASE_URL detection.
- OWASP web Top 10 + OWASP MCP Top 10 detection.
- Output-side sanitiser pipeline.
- Read-only LLM capturer + write-only file ops MCP servers with
  HMAC-signed receipts.
- Read-only file extractor (PDF / DOCX / PPTX / HTML / JSON).
- Scan-before-permit gate using the in-house AgentScanner.
- FastAPI in-house token-bucket rate limiter.
- Electron TS / React / electron-vite migration (vanilla JS removed).
- Bridge lifecycle inside the UI (Start / Stop in header).
- `testudo ui` turnkey CLI launcher.
- `GET /env-check` endpoint + UI badges for Ollama + Databricks readiness.
- File-mode model picker for mistral / minimax-m2.5 / jan-code-4b / chandra-ocr-2.
- DAG composition mode (Compose tab) with `GET /tools` + `POST /workflows`.

## Open user questions

None outstanding. Last user message of session 2026-05-12 was a
sequence of corrections / scope expansions, all addressed in this
sprint.
