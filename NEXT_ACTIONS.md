# Testudo next actions

Companion to `STATUS.md`. Lists what the next session should pick up,
in priority order, with the user's current intent attached.

Refreshed 2026-05-13 after wave 2 follow-ups landed.

## Priority 0 -- v0.1.6 release-blockers

These three close the loop on the "containerised execution" promise the
tagline makes. Until they land, `testudo run` is in-process Python; the
container scaffolding ships unwired.

- **Wire the Docker default execution path.** `testudo run` and the
  bridge's `POST /runs` should default to `docker run` built from the
  workflow's `IsolationProfile`. Stream container stdout / stderr back
  into the audit log. Marshal inputs (workflow JSON + input values) and
  outputs (audit log + written files) across the host-container
  boundary. The argv builder, the Dockerfile, and the Runner already
  exist; v0.1.6 plumbs them.
- **Per-workflow egress allow-list at the iptables layer.** Today
  `IsolationProfile` carries the allow-list as a field but it is not
  enforced beyond the host-side permission check. v0.1.6 enforces at
  the container's `iptables` layer so workflows that need Ollama,
  Databricks, or public HTTPS get exactly the destinations they declare
  and nothing more.
- **CLI helper for ruleset inspection.** `testudo allow-list <workflow.json>`
  prints the merged ruleset (workflow allow-list + operator overrides)
  before the container starts. Lets operators sanity-check the network
  surface in restricted environments (corporate proxy, VPN, on-prem).
- **Wire the prompt template assembler into the orchestrator.** Today
  `testudo.prompts.PromptTemplate` exists with tests; workflow steps
  embed XML inline. v0.1.6 adds a `template:` field to the step schema
  so steps can reference a named template + pass `vars:`.

## Priority 1 -- compose smoke-test round-trip

- Drive `docs/COMPOSE-SMOKE-TEST.md` end-to-end on the UI: build the
  4-step chain on the Compose canvas, save, switch to Workflow tab, run.
  Confirms the `POST /workflows` -> reload -> run cycle works for a
  user-authored composition with no external deps. Should take ~15
  minutes at the desktop.

## Priority 0.5 -- v0.1.7 release-blockers (M365 + Slack)

Behind v0.1.6 (Docker) in sequence, but the headline next release. Full
scope in [docs/ROADMAP.md](docs/ROADMAP.md) and the architectural
rationale in [docs/POSITIONING.md](docs/POSITIONING.md).

- Build `testudo.auth.microsoft` MSAL wrapper (client-credentials +
  device-code flows + token cache + per-workflow scope enforcement).
- Build `testudo.auth.slack` bot-token loader.
- Build `connectors.teams_post`, `connectors.sharepoint_read`,
  `connectors.sharepoint_write`, `connectors.slack_post`.
- Add per-workflow resource binding (channel IDs, site IDs) + refuse-on-
  missing-permission with a clear scope-name error.
- Extend the IsolationProfile egress allow-list automatically for
  `graph.microsoft.com` and `slack.com` when these connectors appear in
  a workflow.
- Ship `testudo m365 doctor` CLI subcommand.
- Ship two example workflows (Teams + Slack variants) with per-workflow
  READMEs.
- Ship `docs/compliance/{SOC2,ISO27001,FedRAMP,GDPR}-*.md` scaffolds.

Realistic timeline: 3-5 sessions. Splittable into v0.1.7-alpha
(auth + Teams) and v0.1.7-beta (SharePoint + Slack + compliance docs).

## Priority 2 -- user-side setup (unblocks several deferred items)

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
  - `spacy`; download `en_core_web_lg` (~750 MB).
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

## Done in wave 2 (do not re-do)

See `STATUS.md` "Post-tag follow-ups, wave 2 (2026-05-13)" for the full
list. Highlights:

- Custom DAG node template (status stripe + tool/id stack + status row).
- Activity panel collapsed-by-default with chevron-expand.
- Two-tier header with the 80s wordmark logo + env strip.
- Floating GIF inset in the WorkflowGraph pane.
- Pre-bridge empty-state visual (dashed outlines + CTA card).
- Workflow READMEs render as HTML (react-markdown + remark-gfm).
- Note input on every run mode threaded through to Activity.
- Quit button in the header.
- Logo asset pipeline (rembg + trim) for the 80s wordmark, full 80s logo, original turtle, and the GIF.
- Socket Firewall install discipline (sfw 1.8.0 + PreToolUse hook + ~/.claude/CLAUDE.md policy).
- Local language packs (Krebs trick) installed.
- `docs/COMPOSE-SMOKE-TEST.md` design committed for the round-trip exercise.

## Done in wave 1 (do not re-do)

See `STATUS.md` "Post-tag follow-ups, wave 1 (2026-05-12)" for the full
list. Highlights:

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
- File-mode model picker with shortlist for common Ollama backends plus free-text override.
- DAG composition mode (Compose tab) with `GET /tools` + `POST /workflows`.
