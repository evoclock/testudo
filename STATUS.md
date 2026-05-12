# Testudo repo status

Snapshot at v0.1.5 + follow-ups, written 2026-05-12. The original
v0.1.5 release section below is frozen as a handover artefact;
"Post-tag follow-ups" captures everything that landed after the tag.

## Top line

- **Version:** 0.1.5 (with multiple follow-up commits on top; see CHANGELOG.md).
- **Tests:** 312 passing, 0 failing, 0 skipped. 87% line coverage.
- **Lint:** `ruff check` clean. `ruff format` clean. Both Electron tsconfigs typecheck clean.
- **License:** Apache 2.0; sole author Julen Gamboa; no co-author bylines on commits.
- **Confidentiality:** zero references to `agentic-orchestrator` or any
  private fork content. testudo is OSS only.

## Post-tag follow-ups (since 2026-05-12 v0.1.5)

- **`testudo ui`** is now a turnkey one-command launcher: generates a token, starts the bridge, polls `/health`, spawns the renderer with the token wired through, cleans up on Ctrl-C.
- **Ollama adapter** (`testudo.models.ollama_chat`); response sanitised before return.
- **DAG composition mode** in the renderer (Compose tab); `GET /tools` and `POST /workflows` bridge endpoints.
- **Five-tab UI** (File / URL / Database / Workflow / Compose) with DAG panel under each mode.
- **Four new bundled workflows** (pdf-debrief, pdf-summarise, url-fetch, db-query).
- **Document extractor** registered as the `connectors.extract_document` orchestrator tool.
- **Test fixtures** for Drive (URL mode) and Databricks (samples.bakehouse + upload path).
- **Logo** wired into the Electron header and the README from `assets/testudo.png`.
- **Drive (private)** dropped from scope; public Drive via `connectors.https_get`.
- **Env templates** (`.env.testudo.example`, `.env.databricks.example`, `.env.ollama.example`).
- **Electron toolchain** bumped to electron ^41 / electron-vite ^5 / vite ^7 / plugin-react ^5; 0 npm vulnerabilities.

Full diff log: see CHANGELOG.md `## [Unreleased] / v0.1.5 follow-ups`.

## Sprint scope (delivered this session)

Driven by user direction across multiple turns on 2026-05-11 / 2026-05-12.
Source resources: SleekFlow data masking, applytosupply G-Cloud listing
110970491105109, AWS Comprehend PII reference, DevOpsSchool top-10
catalogue, Elastic redact processor, hillstar `credential_redactor.py`,
`/home/jgamboa/Downloads/mcp_presentation_v4.pptx`, Microsoft AI
Recommendation Poisoning blog, modelcontextprotocol.io security best
practices.

### 1. Sanitiser expansion (in-house, regex-based)

- `src/testudo/sanitisers/patterns.py` rewritten end-to-end.
  - **UK PII** (unchanged): NIN, email, UK phone, NHS, postcode.
  - **International PII** (expanded): Visa / Mastercard / Amex / Discover
    / JCB / Diners; IBAN; BIC/SWIFT; IPv4; IPv6; MAC; E.164; NA phone;
    DOB (`dd/mm/yyyy` and `yyyy-mm-dd`); Bitcoin; Ethereum.
  - **Country-specific PII** (new, ~50 countries): see CHANGELOG for the
    full list.
  - **Hidden-unicode + comment payloads** (new): zero-width chars; bidi
    overrides; Unicode tag block (E0000-E007F); HTML comments; inline
    base64 data URIs; buried base64 (>=120 chars); `ANTHROPIC_BASE_URL` /
    other API base-URL overrides per CVE-2026-21852.
  - **Prompt injection** (expanded): instruction prelude; "forget the
    above"; "pretend / roleplay" prefix; tool-poisoning marker;
    indirect-injection callback.
  - **OWASP Top 10 web** (new): SQL / NoSQL injection; command injection
    with metachars + process substitution; path traversal raw + encoded
    + absolute-escape; XXE; SSRF (cloud metadata, gopher / file / dict
    protocols); template injection; XSS; LDAP; XPath.
  - **OWASP MCP Top 10** (new): tool poisoning; rug-pull marker;
    SharePoint indirect-injection; instruction-in-document; confused
    deputy; AI recommendation poisoning; skill supply-chain link.
  - **Secrets** (Hillstar parity + extras): all 16 missing patterns
    ported; added Groq, HuggingFace, Twilio, SendGrid, Mailgun, GitHub
    refresh, Slack bot/user, more env-var assignments. JWT 3-segment
    detection. Authorization header. Credentials-JSON fields.
    URL-embedded passwords.
- `src/testudo/sanitisers/unicode_payload.py` (new): `detect_hidden`,
  `strip_hidden`, `sanitise_hidden`. Strips zero-width entirely;
  replaces base64 with `[REDACTED-BASE64-<n>B]`; replaces base-URL
  override with `[REDACTED-BASE-URL-OVERRIDE]`.
- `src/testudo/sanitisers/threat.py` (new): `detect_owasp`,
  `detect_mcp_threats`, `detect_threats`, `sanitise_threat`.
  Severity-aware (CRITICAL for SQL / command / XXE / SSRF; HIGH for
  XSS / template / LDAP / XPath; MEDIUM otherwise).
- `src/testudo/sanitisers/output.py` (new): full output-side pipeline
  per user direction "process the data on input to guard against
  threats and on output too". Order: hidden -> secrets -> PII ->
  injection -> OWASP/MCP. Rejection-priority decision: any injection
  or threat finding -> reject; any earlier-stage finding -> redact;
  else accept. `sanitise_input` is the same pipeline (alias for
  audit-log direction tagging).
- `src/testudo/sanitisers/pii.py` (revised): single-pass collect-then-replace
  in `redact_pii` to avoid the cascading-substitution bug where the BIC/SWIFT
  pattern matched the literal "REDACTED" inside a previous marker.

### 2. Read-only / write-only MCP server architecture

Per user direction "any calls made by an LLM must be returned via an
MCP server with no write permissions, the returned output must be
sanitised first and handed over to the MCP server with read/write
permissions like the file operations MCP server in hillstar
orchestrator".

- `src/testudo/mcp_servers/base.py`: minimal in-house JSON-RPC 2.0
  STDIO server. Handshake, `tools/list`, `tools/call`. No external
  deps. ~100 lines.
- `src/testudo/mcp_servers/llm_response_capturer.py`: read-only.
  Captures LLM tool-call output. Runs `sanitise_output`. Issues an
  HMAC-signed receipt over `(run_id, sha256(content), decision)` keyed
  by `TESTUDO_RECEIPT_KEY`. Rejected payloads carry a receipt that the
  writer refuses.
- `src/testudo/mcp_servers/file_writer.py`: write-only. Modelled on
  hillstar's `file_operations_mcp_server.py`. Path validation against
  `TESTUDO_REPO_ROOT`. Every write requires a valid receipt; tampered
  content fails the signature check; rejected-decision receipts fail
  the policy check.
- `src/testudo/mcp_servers/file_extractor.py`: read-only. PDF / DOCX /
  PPTX / HTML / JSON / plain-text. PPTX uses stdlib `zipfile` (no
  `python-pptx` runtime dep). PDF / DOCX behind the `[file_ops]`
  extra; missing extras yield a clean `isError` rather than a crash.
  Output goes through `strip_hidden` before returning.

### 3. Permissions

- `src/testudo/permissions/scan.py` (new): scan-before-permit gate.
  - `should_scan(path)`: heuristic for MCP-config-like artifacts
    (`.mcp.json`, `.claude.json`, `claude_desktop_config.json`,
    `*.md` in `.claude/` / `.cursor/` / `.windsurf/` / `skills/`,
    paths with `skill` in the name).
  - `require_filesystem_read_scanned` /
    `require_filesystem_write_scanned`: scan first, then plain
    permission check. Any HIGH or CRITICAL finding raises
    `ScanRejected` before the path check fires.
  - `evaluate_scan(result, block_severity=)`: pure summary helper.
- Permissions package exports both old and new gates; v0.2 will flip
  the default once the call sites are audited.
- `permissions/scan.py` lazy-imports `AgentScanner` to avoid the
  `permissions <-> sanitisers` circular-import chain that
  `sanitisers/tools.py` introduces via the orchestrator registry.

### 4. FastAPI bridge

- `src/testudo/server/rate_limit.py` (new): in-house `TokenBucket` +
  `RateLimiter` + `RateLimitMiddleware`. Per-bearer-token keying with
  `X-Forwarded-For` / client-host fallback. `/health` and `/metrics`
  exempt. 429 + Retry-After on bucket exhaustion.
- `src/testudo/server/app.py`: `RateLimitMiddleware` wired in.
  `create_app` accepts an optional `rate_limit=` for tests.

### 5. Electron migration (TS + React + electron-vite)

Per user direction "TS and Node/React from the word go". Removed the
vanilla-JS scaffold entirely; replaced with electron-vite project.

- `electron/package.json`: bumped to 0.1.5; switched to ESM (`type:
  module`); added React 18, React Flow, Tailwind, electron-vite, Vite,
  TypeScript, ESLint, Prettier, Autoprefixer, PostCSS.
- `electron/tsconfig.{json,node.json,web.json}`: split tsconfigs for
  Node lib (main / preload) vs DOM lib (renderer).
- `electron/electron.vite.config.ts`: Vite config with `react()` for
  the renderer and `externalizeDepsPlugin` for main / preload.
- `electron/postcss.config.js` + `electron/tailwind.config.ts`:
  Tailwind v3 + Autoprefixer with the project's color palette
  (bg / panel / border / accent / muted / text).
- `electron/src/main/index.ts`: TS main process. BrowserWindow with
  `sandbox: true`, `contextIsolation: true`, `nodeIntegration: false`.
  Reads `TESTUDO_BRIDGE_URL` and `TESTUDO_BRIDGE_TOKEN` from env;
  forwards to renderer via IPC. `testudo:openFile` and
  `testudo:spawnServe` IPC handlers.
- `electron/src/preload/index.ts`: TS preload. `contextBridge`
  exposes `window.testudo` with typed `getBridgeConfig`, `openFile`,
  `spawnServe`. `index.d.ts` augments `Window`.
- `electron/src/renderer/`: React 18 entry (`main.tsx`, `App.tsx`,
  `index.css`). Three components: `Sidebar` (workflow list), `Chat`
  (message log + textarea + attach), `WorkflowGraph` (React Flow
  rendering of step DAG).
- `electron/src/renderer/src/lib/api.ts`: typed FastAPI client
  (`BridgeClient`, `makeBridgeClient`) wired to the preload-injected
  config.
- `electron/README.md`: TS / vite / contextBridge documentation.
- `electron/.gitignore`: node_modules, out, dist, build, .cache.

`npm install` not run (network-bound); user runs it before
`npm run dev`.

## Test breakdown

| Area | New tests | File |
|------|-----------|------|
| hidden-unicode + comment payloads | 11 | `tests/test_sanitisers_unicode_payload.py` |
| OWASP + MCP threat detectors | 12 | `tests/test_sanitisers_threat.py` |
| Output sanitiser pipeline | 7 | `tests/test_sanitisers_output.py` |
| Scan-before-permit gate | 4 | `tests/test_permissions_scan.py` |
| MCP servers (base + capturer + writer + extractor) | 14 | `tests/test_mcp_servers.py` |
| FastAPI rate limiter | 7 | `tests/test_server_rate_limit.py` |
| Existing v0.1 tests | 213 | unchanged |

Total: 279 (was 213).

## Files created this sprint

```text
electron/.gitignore
electron/electron.vite.config.ts
electron/postcss.config.js
electron/src/main/index.ts
electron/src/preload/index.d.ts
electron/src/preload/index.ts
electron/src/renderer/index.html
electron/src/renderer/src/App.tsx
electron/src/renderer/src/components/Chat.tsx
electron/src/renderer/src/components/Sidebar.tsx
electron/src/renderer/src/components/WorkflowGraph.tsx
electron/src/renderer/src/index.css
electron/src/renderer/src/lib/api.ts
electron/src/renderer/src/main.tsx
electron/tailwind.config.ts
electron/tsconfig.json
electron/tsconfig.node.json
electron/tsconfig.web.json
src/testudo/mcp_servers/__init__.py
src/testudo/mcp_servers/base.py
src/testudo/mcp_servers/file_extractor.py
src/testudo/mcp_servers/file_writer.py
src/testudo/mcp_servers/llm_response_capturer.py
src/testudo/permissions/scan.py
src/testudo/sanitisers/output.py
src/testudo/sanitisers/threat.py
src/testudo/sanitisers/unicode_payload.py
src/testudo/server/rate_limit.py
tests/test_mcp_servers.py
tests/test_permissions_scan.py
tests/test_sanitisers_output.py
tests/test_sanitisers_threat.py
tests/test_sanitisers_unicode_payload.py
tests/test_server_rate_limit.py
STATUS.md
NEXT_ACTIONS.md
```

## Files modified this sprint

```text
CHANGELOG.md (new [0.1.5] section, deferred-to-v0.1.5 section removed)
README.md (no major changes; pointer references unchanged)
electron/README.md (TS/Vite documentation)
electron/package.json (TS toolchain dependencies)
pyproject.toml (version bump 0.0.1 -> 0.1.5; new file_ops extra)
src/testudo/__init__.py (version bump)
src/testudo/permissions/__init__.py (export scan helpers)
src/testudo/sanitisers/__init__.py (export new modules)
src/testudo/sanitisers/patterns.py (rewritten end-to-end)
src/testudo/sanitisers/pii.py (single-pass redact)
src/testudo/server/app.py (rate-limit middleware)
```

## Files removed this sprint

```text
electron/main.js
electron/preload.js
electron/renderer/index.html
electron/renderer/ (directory)
```

## Confidentiality / privacy

- Zero references to `agentic-orchestrator/` or any private-fork
  content in the diff.
- The agent scanner is an in-house port of hillstar's
  `workflows/agent_scanner.py`; the redactor is an in-house
  superset of hillstar's `utils/credential_redactor.py`. Both live
  inside testudo. No runtime dependency on hillstar.
- The MCP file writer is patterned on hillstar's
  `mcp-server/file_operations_mcp_server.py` (path validation +
  three tools). Receipt verification is a testudo addition not
  present in hillstar.

## Known gaps (pre-commit, not blockers)

- `electron/` has no `node_modules/` yet. User runs `npm install`
  to bring up the renderer.
- Coverage is 87%, not 90%+. The new MCP-server `if __name__ ==
  "__main__"` blocks are uncovered (intentional; they're the STDIO
  entry-points). Some `_loaded.py` paths and the `cli.py` UI path
  are also under-covered.
- Pyright noise persists in IDE; the Pyright instance points at
  system Python rather than `.venv`. Runtime imports work; tests
  pass; ruff is clean. No code change required.
