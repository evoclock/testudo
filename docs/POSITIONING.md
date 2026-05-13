---
title: "Testudo positioning - vs restrictive enterprise agent platforms"
---

## Scope

This doc covers Testudo's positioning against the class of restrictive
enterprise agentic-platform products: vendor-locked SaaS with heavy
licensing, no-code-targeted authoring, centralised tenant
administration, and opaque content moderation. Microsoft Copilot Studio
is the lead example throughout because it is the most concrete and the
most likely starting point for operators arriving at Testudo. The same
gap analysis and close-the-gap plan apply to any vendor product with
equivalent shape.

Captures:

1. The connector gap as of today (2026-05-13).
2. Where Testudo undercuts these platforms on friction and where it
   does not.
3. Where Testudo is stronger on data-path security and where it is not.
4. A close-the-gap plan, friction point by friction point, with the
   architectural choices made explicit.

Position: Testudo is the right shape for **a single technical operator
or small team** that needs auditable, sandboxed, declarative agentic
workflows on locked-down infrastructure. It is not aimed at no-code
users. Once the M365 + Slack connector trio lands in v0.1.7, the
"process file -> post to Teams" use case is achievable with stronger
data-path security than the vendor-platform alternatives.

## The restrictive-platform category

Testudo competes (or rather, declines to compete) with this class of
product:

| Product | Vendor | Anchor stack |
|---|---|---|
| Microsoft Copilot Studio | Microsoft | Power Platform + M365 + Azure OpenAI |
| Microsoft Copilot Agents (Copilot Pages, Copilot for Teams) | Microsoft | M365 + Azure |
| Vertex AI Agent Builder | Google Cloud | GCP + Gemini |
| Bedrock Agents | AWS | AWS + Anthropic / Titan / etc. |
| Agentforce | Salesforce | Data Cloud + Einstein |
| Now Assist Agentic AI | ServiceNow | Now Platform |
| watsonx Orchestrate | IBM | watsonx + Cloud Pak |
| Rovo Agents | Atlassian | Jira / Confluence + their model gateway |
| Notion AI agents | Notion | Notion data + their model gateway |
| Zapier Agents | Zapier | Zapier triggers + OpenAI |
| Glean Assistants | Glean | their search index + model gateway |

Common shape across the category:

- Authoring is GUI-first, pitched at non-technical users.
- Connectors come from a vendor-curated marketplace; building your own
  is gated by vendor processes (Power Platform Custom Connector
  approval, AWS partner programs, etc.).
- Authentication is vendor-tenant-bound (Entra ID, Google Workspace,
  AWS IAM, Salesforce Identity).
- Data residency and content moderation are vendor-defined; the
  operator inherits whatever the vendor permits and audits.
- Cost scales with seats, runs, tokens, or some combination thereof.
- Open source: not applicable; the runtime is closed.
- Deployment target: vendor-hosted SaaS by default.

When Testudo is the right shape:

- You want auditable defence-in-depth before data crosses any
  network boundary.
- You want workflow definitions in git, code-reviewable.
- You want a single technical operator (or small team) to ship without
  a license budget or admin-approval chain.
- You want the connectors and the sanitiser stack open for inspection.
- Your AUP permits running approved models locally; you do not need a
  multi-tenant management surface.

When the vendor platform is the right shape:

- 5000-user enterprise rollout requiring centralised admin, DLP, and
  vendor-attested compliance.
- Non-technical users authoring their own agents.
- You already pay for the licensing and want zero build cost.

Throughout this doc, "Copilot Studio" can be read as shorthand for "any
vendor product in the table above". Specific claims about Microsoft
features (Power Platform DLP, Entra ID, Microsoft Graph) substitute
straightforwardly with the vendor's equivalent (Google Cloud DLP,
Google Workspace, Google Drive API; AWS IAM, AWS DLP, S3; etc.).

## Adapter / connector inventory today

The runtime, sandbox, and sanitiser story is in place. The connector
library is sparse.

| Category | Available today |
|---|---|
| Inputs | `connectors.local_file`, `connectors.https_get`, `connectors.extract_document` (PDF / DOCX / PPTX / HTML / JSON / TXT / MD) |
| Data | `data.duckdb_query`, `data.databricks_query` |
| Models | `models.ollama_chat` (local + Ollama Cloud); Anthropic / OpenAI / Mistral / Google planned for v0.2 |
| Outputs | `outputs.file`, `outputs.chat`, `outputs.dashboard`, `outputs.ticket` |
| Missing for the M365 use case | `connectors.teams_post`, `connectors.slack_post`, `connectors.sharepoint_io` |

Auth helpers today: none for Microsoft Graph; ad-hoc env loading for
Databricks. The v0.1.7 work below builds the M365 + Slack auth layer
on the existing env-loader pattern.

## Friction comparison

### Where Testudo is lower friction than Copilot Studio

- No Azure subscription, Power Platform licenses, or M365 tenant admin
  approval required to develop.
- Workflow definitions are JSON in git: diffable, code-reviewable,
  version-controlled.
- Local development, no staging environments.
- Open source. Every line of code that handles your data is auditable.
- No vendor lock-in.

### Where Testudo is higher friction today

- No drag-drop GUI for non-technical users (Compose is for technical
  users authoring workflow JSON visually). See closure note below.
- No marketplace of pre-built connectors. You build what you need.
- No built-in M365 auth surface. Today you would provision Azure app
  registrations manually.
- DIY infrastructure (host, container runtime, observability).

## Security comparison

### Where Testudo is stronger than Copilot Studio for this use case

- Model output passes through the output-side sanitiser pipeline
  **before** reaching Teams / Slack / SharePoint: hidden-unicode strip
  -> secret redact -> PII redact (UK + ~50 country patterns) ->
  injection detect -> OWASP web + MCP Top 10 detect. Copilot Studio's
  content moderation does not gate against country-specific PII at the
  fidelity of Testudo's regex stack.
- Read-only LLM capturer + write-only file writer with HMAC-signed
  receipts: anything an LLM emits cannot reach a write capability
  without a valid receipt over the sanitised content.
- Container isolation per workflow with declared egress allow-list
  (v0.1.6 enforces at iptables). Copilot Studio's network surface is
  whatever Microsoft permits across the whole Power Platform tenant.
- Sandbox + sanitiser + audit are auditable by reading the code, not by
  trusting a vendor's assurances.

### Where Copilot Studio is stronger

- Microsoft's compliance attestations (SOC 2 Type II, ISO 27001,
  FedRAMP Moderate, GDPR data residency in EU regions). Testudo is a
  runtime an operator deploys; certifications attach to the deployment,
  not the codebase. Closure plan below.
- Centralised tenant admin via Power Platform admin centre, DLP policy
  framework, conditional access via Entra ID. Testudo explicitly does
  not duplicate this surface; closure plan moves the gate to the
  external resource layer instead.
- Pre-audited connectors with Microsoft's threat intel behind them.
  Testudo's connector layer is open source; threat intel lives in the
  in-house sanitiser stack and Socket Firewall at install time.
- Identity infrastructure (MFA, conditional access, audit log
  integration with Sentinel / Defender). Testudo issues per-run audit
  logs in JSONL; integration with SIEM systems is a deployer-side
  exercise today.

## Close-the-gap plan

Friction point by friction point, with the architectural choice
documented. The plan deliberately rejects two paths and commits to
seven.

### 1. Low-code yes, no-code no

**Position**: Testudo offers **low-code** authoring through the Compose
canvas: tool palette, React Flow editing surface, per-node param
inspector, save-as-workflow-JSON. The author drags and wires; they do
not need to write Python. That is the GUI ceiling and a deliberate one.
Testudo does **not** offer a **no-code** "describe in English what you
want and we will generate the agent" surface.

**Why the distinction matters**: low-code removes the typing burden;
no-code claims to remove the understanding burden too. The
understanding cannot actually be removed. Agentic-tooling failure
modes are subtle. A misconfigured connector silently leaks data to a
destination the operator did not intend; a prompt-injection chain
produces output that looks correct but is wrong; a sanitiser misapplied
to the wrong field redacts the signal and ships the noise. The "anyone
can build an agent" position is appealing as a marketing line but
tends to externalise the cost of these failure modes onto downstream
consumers (the people who receive the bad output), and developer time spent fixing the solution.

Testudo's position: the assumption of good system-design and
implementation understanding rests with the author. Compose makes that
authoring lighter (you compose from primitives rather than write code),
not optional (you still need to know what each primitive does and how
they compose). The required understanding includes: which connectors
touch the network, what each sanitiser pass means for the data
flowing through, how the isolation profile bounds the blast radius if
a step misbehaves, when to use a chat-channel output versus a file
write, why XML-tagged prompt templates are the convention.

**What we will do** (technical-user comfort, not lower the
understanding bar):

- Template gallery: fork-from-template flow in Compose. Each shipped
  workflow becomes a starter template so the author starts from a
  working example rather than a blank canvas.
- "Test step" action in Compose's node inspector: run an isolated step
  with synthetic inputs and surface the output / error inline.
- Param validation feedback in Compose (already present for missing
  required inputs; extend to type-mismatch and schema-violation hints).
- Inline JSON view alongside the canvas for authors who want to edit
  the underlying workflow.json directly.
- In-app hover-help for every connector and sanitiser describing what
  it does, what data it touches, and what its failure modes are.
- A short "what could go wrong" linting pass in Compose that flags
  patterns known to misbehave (e.g. an `outputs.file` step writing to
  a path outside the workflow's filesystem allow-list; a `models.*`
  step whose downstream consumers do not run `sanitise_output` first).

**What we will do instead** (technical-user comfort, not no-code):

- Template gallery: fork-from-template flow in Compose. Each shipped
  workflow becomes a starter template.
- "Test step" action in Compose's node inspector: run an isolated step
  with synthetic inputs and surface the output / error inline.
- Param validation feedback in Compose (already present for missing
  required inputs; extend to type-mismatch and schema-violation hints).
- Inline JSON view alongside the canvas for users who want to edit the
  underlying workflow.json directly.

### 2. No marketplace - Not something we want as a solution at this time

**Decision**: we do not build a third-party connector marketplace.
Connectors live in `src/testudo/connectors/` and `src/testudo/data/`
under the same code review and sanitiser-pass discipline as the rest of
the codebase.

**Reason**: a marketplace is a supply-chain attack surface. The
@tanstack/* compromise on 2026-05-13 illustrated the failure mode. We
ship a small set of well-audited connectors and operators add their own
under their own review discipline; we do not host arbitrary
third-party code.

### 3. M365 auth - SHIPPED v0.1.7

**Decision**: build `testudo.auth.microsoft` as an MSAL wrapper that
supports both auth flows.

- **Client credentials flow** (service principal): the agent has its
  own identity in Entra ID. Loads `tenant_id`, `client_id`,
  `client_secret` from `.env.microsoft`. Right shape for "an agent runs
  as a service account and posts to a shared channel".
- **Device code flow** (delegated user): the operator authenticates
  interactively the first time; refresh tokens cached locally. Right
  shape for "the agent acts on behalf of the logged-in user" so audit
  trail attributes actions correctly.

Token cache: file-based, gitignored, in `~/.config/testudo/tokens/`.
Proactive refresh before expiry. Per-workflow scope declaration in
`permissions.microsoft.scopes`; runtime enforces.

CLI helper: `testudo m365 doctor` prints the exact Azure app
registration steps (redirect URIs, API permissions, admin consent URL)
the operator needs to follow.

### 4. Per-resource gate, not centralised tenant admin - SHIPPED v0.1.7

**Decision**: Testudo does not host a multi-tenant management surface.
There is no internal admin screen for environment provisioning, DLP
policies, or user lifecycle. The deployment is single-operator.

**Why**: centralised tenant admin causes more headaches than it is
worth at Testudo's deployment scale. The right model is to gate at the
**external resource layer**: a SharePoint site, Teams channel, or
Slack workspace approves the agent's app at the source. Microsoft Graph
already has per-site / per-team permission granting; Slack already has
per-workspace app approval. We do not reinvent this.

**What we do build**:

- Per-workflow resource binding in `workflow.json`: explicit channel
  IDs, site IDs, drive IDs. No "the agent can post anywhere" mode.
- Refuse to run a workflow whose declared resource IDs are not granted
  by the loaded tokens; surface the missing permission with the exact
  scope name the operator must request from their Microsoft / Slack
  admin.
- Document each connector's required Microsoft Graph scopes / Slack
  scopes so the operator can request only the minimum needed.

**What we do not build**:

- A Testudo-side admin screen for granting access.
- A multi-tenant identity model.
- A DLP framework. DLP belongs at the SharePoint / Microsoft Purview
  layer, where it already exists.

### 5. Compliance attestations - tackled one by one

Testudo is a runtime; the deployer is the certifiable entity. What
Testudo ships is a control-mapping doc so a deployer's auditor can see
how Testudo features satisfy each framework's controls.

#### SOC 2 Type II

What it is: an external auditor reviews controls over 6-12 months
against the AICPA Trust Services Criteria (security, availability,
processing integrity, confidentiality, privacy). Typical evidence
collection automated by Drata / Vanta / Secureframe.

How Testudo supports the deployer's certification:

- Security: defence-in-depth sanitiser pipeline + permissions framework
  - scan-before-permit gate + container isolation profile.
- Availability: per-run audit log captures every workflow start /
  step / error / completion with timestamps. Bridge has health
  endpoint.
- Processing integrity: HMAC-signed receipts over LLM output ensure
  data-in-transit between the read-only capturer and the write-only
  writer cannot be tampered with.
- Confidentiality: bearer-token auth on the bridge; rate limiter
  blocks brute force; container isolation prevents step-to-step
  cross-contamination.
- Privacy: PII detection across ~50 country patterns, redaction on
  the output side; data residency declarable per workflow (see GDPR).

Documentation deliverable: `docs/compliance/SOC2-control-mapping.md`.

#### ISO 27001

What it is: ISMS certification of an organisation against the standard
plus Annex A controls (A.5 policies, A.8 asset management, A.9 access
control, A.12 operations security, A.14 system acquisition /
development, etc.). Not a product certification.

How Testudo supports the deployer's certification: same defence-in-
depth posture documented against Annex A control numbers. For each
relevant control we point at the Testudo feature that satisfies it
(e.g. A.9.2.3 management of privileged access rights -> Permissions
framework + scan-before-permit gate; A.12.4 logging and monitoring ->
audit log JSONL with documented schema).

Documentation deliverable: `docs/compliance/ISO27001-Annex-A-mapping.md`.

#### FedRAMP

What it is: US federal cloud authorisation against NIST 800-53. Three
impact levels (Low, Moderate, High). Requires deployment in a
FedRAMP-authorised infrastructure (Azure Government, AWS GovCloud).
1-2 year process with a 3PAO assessor.

How Testudo supports the deployer's authorisation:

- Cryptographic posture: HMAC-SHA256 receipts. SHA-256 is FIPS-140-2
  approved. If a US fed customer needs FIPS-validated crypto modules,
  the deployer uses a FIPS-validated Python build (e.g. RHEL UBI FIPS
  image).
- Supply chain: SLSA build provenance for releases (v0.3 roadmap item).
  In the interim: signed git tags, reproducible builds via uv lock,
  pre-commit hooks documented.
- Continuous monitoring: per-run audit log feeds an external SIEM via
  log shipping; no Testudo-side requirement.

Documentation deliverable: `docs/compliance/FedRAMP-readiness.md`.
Realistic timeline: a deployer pursuing FedRAMP Moderate authorisation
would need 12-18 months. Testudo can be FedRAMP-ready in a few weeks
of doc work; the certification itself is the deployer's lift.

#### GDPR data residency

What it is: not a certification. Demonstrable compliance. The two
relevant questions are (a) where is personal data stored and processed
and (b) what lawful basis covers the processing.

How Testudo supports compliance:

- Local-first by default: data never leaves the host unless a connector
  wires it elsewhere. Per-workflow data-flow documentation makes this
  enumerable.
- Per-workflow `data_residency:` field in the `IsolationProfile`
  declaring allowed regions; runtime enforces at the connector layer.
  Example: a workflow declaring `data_residency: [EU, UK]` cannot bind
  to a Microsoft Graph site in a US region; the binding refuses with a
  clear error.
- `:cloud` suffix Ollama models route to Ollama's hosted
  infrastructure which is not EU-resident. Documented in
  `OLLAMA_SETUP.md` as a GDPR caveat. For strict environments use
  local-only models.
- Microsoft Graph honours data residency at the tenant level (EU / UK
  tenants stay in EU / UK data centres). Testudo's connector binds to
  the tenant; tenant residency carries through.

Documentation deliverable: `docs/compliance/GDPR-data-flow.md` plus
per-workflow data-flow declarations.

## v0.1.7 release milestone

Headline: Microsoft 365 + Slack connectors + auth helper.

### Scope

| Item | File / location | Effort |
|---|---|---|
| `testudo.auth.microsoft` MSAL wrapper (client creds + device code, token cache, scope enforcement) | `src/testudo/auth/microsoft.py` + tests | ~300 lines + tests |
| `testudo.auth.slack` bot token loader (no refresh; static bot tokens) | `src/testudo/auth/slack.py` + tests | ~80 lines + tests |
| `connectors.teams_post` (Microsoft Graph `/teams/{id}/channels/{id}/messages`) | `src/testudo/connectors/microsoft.py` + tests | ~150 lines + tests |
| `connectors.sharepoint_read` + `connectors.sharepoint_write` (Microsoft Graph `/sites/{id}/drives/{id}/items`) | `src/testudo/connectors/microsoft.py` (same module) + tests | ~250 lines + tests |
| `connectors.slack_post` (Slack `chat.postMessage`) | `src/testudo/connectors/slack.py` + tests | ~120 lines + tests |
| `.env.microsoft.example`, `.env.slack.example` templates | repo root | docs |
| `testudo m365 doctor` CLI | `src/testudo/cli.py` (new subcommand) | ~150 lines |
| Per-workflow scope declaration in `permissions.microsoft.scopes` and `permissions.slack.scopes`; runtime enforcement | `src/testudo/permissions/` extension | ~100 lines + tests |
| Per-resource binding in workflow JSON (channel / site / drive IDs); refuse on missing permission | `src/testudo/orchestrator/loader.py` + executor enforcement | ~80 lines + tests |
| Egress allow-list automatically includes `graph.microsoft.com` and `slack.com` when these connectors appear in a workflow | `src/testudo/runtime/isolation_profile.py` | ~40 lines + tests |
| Compliance docs scaffold: `docs/compliance/{SOC2,ISO27001,FedRAMP,GDPR}-*.md` | docs | doc-only |
| Example workflows: `workflow-sharepoint-summarise-teams-post.json`, `workflow-sharepoint-summarise-slack-post.json` | `examples/` + readmes | docs |

### Development timeline

Split into two phases:

- **v0.1.7-alpha**: auth helpers + Teams connector + scope enforcement
  - one example workflow. End-to-end demo possible.
- **v0.1.7-beta**: SharePoint connectors + Slack connector + compliance
  doc scaffold + second example workflow.

### What this milestone does not include

- Compliance certification itself. The deployer pursues this with an
  auditor. We ship the control-mapping docs and the technical posture.
- A Power Automate-style connector marketplace. Per the rejection in
  section 2 above.
- A no-code authoring layer. Per the rejection in section 1 above.
- Multi-tenant management. Per the rejection in section 4 above.

## When to use Testudo vs Copilot Studio - decision matrix

| Situation | Recommended |
|---|---|
| Personal or single-team pilot, "process file -> sanitise -> post to Teams" | Testudo (post v0.1.7) |
| Locked-down corporate machine, Copilot-only policy, can run local Ollama | Testudo if your AUP allows local LLMs at all; otherwise neither |
| Sensitive data (PII / secrets / regulated content) that must be sanitised before reaching M365 | Testudo, even pre-v0.1.7 - the data-path security depth is the differentiator |
| Open-source / auditability requirement | Testudo |
| You need a workable dev loop on the agent itself: prototype, test, validate, score outputs, iterate. This is the case **even when only vendor-approved models are available** | Testudo - see "The broken dev loop" below |
| 5000-user enterprise rollout, global compliance, central tenant admin needed | Copilot Studio - Testudo's deliberate architectural choices do not target this scope |
| Non-technical users authoring their own agents | Copilot Studio - Testudo will not be no-code by design |
| You already pay for E5 / Power Platform; want zero build cost | Copilot Studio - the lift Testudo asks of the operator is real even if small |

## The broken dev loop on vendor-GUI platforms

The most-cited reason for adopting Testudo in environments that already
have Copilot Studio or Power Automate licensing is not model availability;
it is that the **development loop itself is broken** on GUI-first platforms,
regardless of which approved model the agent points at:

- **Prototyping**: every iteration is a click-through in the flow
  editor. There is no diff between version N and N+1; reviewing what
  changed means walking the canvas. Reverting means manually undoing
  steps in a particular order. There is no `git checkout`.
- **Testing**: workflow definitions are not unit-testable as code. No
  pytest, no fixtures, no CI run that says "the workflow's contract
  still holds after this change". Validation is "click Test and watch
  it run".
- **Validation**: assertions about workflow behaviour (this step must
  not reach the network; this output must never contain PII; this run
  must complete within N seconds) have no declarative home. Each one
  becomes a manual check or a side-channel monitor.
- **Output scoring**: rating the quality of generated outputs against
  a held-out set or a rubric is a separate exercise in a separate
  tool. There is no place inside the platform to put a scoring step,
  collect scores, and gate releases on a regression threshold.
- **Iteration speed**: the round trip from "I think this prompt would
  be better" to "the agent now uses the new prompt and I can see the
  effect" is measured in minutes per change at best. Compared to a
  text-editor save + rerun cycle, the gap is two orders of magnitude.

Testudo's answers, all native:

- Workflow JSON in git. Diffable, reviewable, revertible, mergeable.
- Tests are `pytest`. Each example workflow ships with a smoke test;
  the CI matrix runs them on every push.
- Validation is declarative in the workflow itself:
  `permissions.network.egress` is the explicit allow-list, `when:`
  predicates short-circuit unsafe branches, sanitisers reject before
  exit. The audit log records the verdict per step.
- Output scoring is just another step. Add a `models.ollama_chat` step
  that scores the previous step's output against a rubric; aggregate
  with `outputs.dashboard`; gate the next CI release on the score with
  a `when:` predicate. The whole loop lives in the workflow shape that
  already produced the output you are scoring.
- Iteration speed is whatever your terminal cycle is. Edit JSON, save,
  `testudo run`, observe. No GUI in between.

This is independent of the model-availability argument. Even with
Copilot Studio configured to use the same `:cloud` Ollama models or the
same Azure OpenAI deployment Testudo would call, the dev loop on the
vendor platform remains GUI-bound. For teams that need to build, test,
and ship agents iteratively, the vendor platform imposes a real cost
that compounds across every prototype cycle.

## Related

- [ROADMAP.md](ROADMAP.md) - v0.1.7 milestone scope.
- [ARCHITECTURE.md](ARCHITECTURE.md) - the layers that satisfy each compliance control.
- [OLLAMA_SETUP.md](OLLAMA_SETUP.md) - local-only vs `:cloud` model choice for GDPR-strict environments.
- [`commercial/vogelkop-ui-stack.md` in the project-planning hub] - related decision about UI stack for any future Hillstar-adjacent commercial UI.
