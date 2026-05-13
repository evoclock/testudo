---
title: "Testudo ISO/IEC 27001:2022 Annex A control mapping"
status: draft
last_updated: 2026-05-13
---

## Status

**Draft scaffold.** Part of the v0.1.7 milestone (see
[../ROADMAP.md](../ROADMAP.md)). The structure and the Testudo-side
feature mapping are in place; deployer evidence requirements will be
filled in as v0.1.7 lands.

## Scope and audience

This document maps Testudo features to ISO/IEC 27001:2022 Annex A
controls so a deployer pursuing ISO 27001 certification has a clear
view of which controls Testudo helps satisfy.

**Important framing**: ISO 27001 certifies an organisation's
Information Security Management System (ISMS), not a product. The
deployer is the certifiable entity. Testudo features map to specific
Annex A controls; the deployer presents Testudo (alongside other
controls) as part of their ISMS during the certification audit.

ISO 27001:2022 reduced Annex A from the 14 control families in the
2013 version to four themes (Organisational, People, Physical,
Technological) covering 93 controls. The mapping below focuses on the
Technological theme (A.8) plus the Organisational controls (A.5) that
Testudo directly supports.

## Annex A control mapping

### A.5 Organisational controls

| Control | Testudo feature | Deployer responsibility |
|---|---|---|
| A.5.7 Threat intelligence | In-house sanitiser stack (OWASP web + MCP Top 10 detection, prompt-injection patterns, hidden-unicode, ~50 country PII patterns); Socket Firewall on every package install | Subscribe to upstream advisories; update sanitiser ruleset on a cadence; review pre-commit hook output |
| A.5.10 Acceptable use of information | Per-workflow `Permissions` model (filesystem prefixes, network egress allow-list, process spawn) | Document AUP referencing workflow-level permission declarations |
| A.5.23 Information security for cloud services | Container `IsolationProfile` with declared egress; per-workflow resource binding (v0.1.7) for Microsoft Graph / Slack | Vendor due diligence for any cloud service the workflow binds to |
| A.5.30 ICT readiness for business continuity | Workflow definitions in git; failed runtime rebuildable from JSON + input data | Backup, restore, and continuity tests of the deployer's hosting infrastructure |

### A.6 People controls

These attach to the deployer's HR / training programme. Testudo
provides no direct controls.

### A.7 Physical controls

These attach to the deployer's facility / hosting infrastructure.
Testudo provides no direct controls.

### A.8 Technological controls

| Control | Testudo feature | Deployer responsibility |
|---|---|---|
| A.8.1 User endpoint devices | (Operator-side; out of scope) | Endpoint management policy |
| A.8.2 Privileged access rights | `Permissions` model + scan-before-permit gate; bearer-token auth on the bridge | Bearer-token issuance and rotation policy |
| A.8.3 Information access restriction | `permissions.filesystem.read` / `write` prefix allow-lists; container filesystem isolation | Per-workflow path declarations in git |
| A.8.4 Access to source code | Repository is git; pre-commit hook enforces ruff format + ruff check + mypy + detect-private-key | Branch protection rules on the deployer's clone; code review policy |
| A.8.5 Secure authentication | Bearer-token auth on the bridge; v0.1.7 adds MSAL (client-credentials + device-code flows) for Microsoft Graph | Token cache hygiene; MFA on the deployer's identity provider |
| A.8.7 Protection against malware | `AgentScanner` + scan-before-permit gate; Socket Firewall install discipline; HMAC-signed receipts prevent tampered LLM output reaching disk | Anti-malware on the host; SIEM integration |
| A.8.8 Management of technical vulnerabilities | `npm audit`, `pip-audit`, pre-commit hook, CI matrix on Python 3.11 + 3.12 | Vulnerability triage cadence; advisory subscriptions |
| A.8.9 Configuration management | Workflow definitions and `IsolationProfile` in git; `.pre-commit-config.yaml` codifies lint / type / safety checks | Git tag policy per release; change approval workflow |
| A.8.10 Information deletion | Per-run audit logs are append-only; deployer's log retention policy governs deletion | Log retention configuration; secure-deletion procedures |
| A.8.11 Data masking | Sanitiser output-side pipeline: hidden-unicode strip -> secret redact -> PII redact -> injection detect -> OWASP / MCP threat detect | Mask rule version pinning per release |
| A.8.12 Data leakage prevention | Per-workflow egress allow-list at the iptables layer (v0.1.6); sanitiser output-side pipeline before any network egress | DLP framework at the SharePoint / Microsoft Purview / Slack DLP layer |
| A.8.13 Information backup | Per-run audit logs in JSONL; outputs to declared paths | Backup procedure for audit logs and outputs |
| A.8.15 Logging | Per-run audit log with `workflow_start`, `step_start`, `step_end`, `permission_*`, `error` events in JSONL | Log shipping to a SIEM; retention policy |
| A.8.16 Monitoring activities | Audit log feeds an external SIEM; rate limiter blocks brute force on the bridge | SOC / SIEM monitoring; alerting rules |
| A.8.17 Clock synchronisation | All audit timestamps in UTC ISO 8601 | NTP on the host |
| A.8.21 Security of network services | Container `IsolationProfile` defaults to `--network=none`; v0.1.6 enforces per-workflow allow-list at iptables | Network segmentation at the host or VPC layer |
| A.8.23 Web filtering | Workflow-level network egress allow-list bounds what destinations the agent can reach | Forward proxy or DNS filtering at the network egress |
| A.8.24 Use of cryptography | HMAC-SHA256 receipts; TLS on the bridge; bearer-token randomness from `secrets.token_urlsafe` | Cryptographic policy; FIPS-validated build for federal scope |
| A.8.25 Secure development lifecycle | Pre-commit hook, CI matrix, code review on every commit, sanitiser regression test corpus (316 tests) | SDLC policy; design review for new connectors |
| A.8.26 Application security requirements | Defence-in-depth (sanitisation -> permission -> scan -> MCP separation -> audit); declarative per-workflow | Security requirements catalogue per workflow |
| A.8.27 Secure system architecture | Container per workflow with declared `IsolationProfile`; read-only / write-only MCP server separation; HMAC receipts | Architecture review on every workflow addition |
| A.8.28 Secure coding | `ruff check`, `ruff format`, `mypy --strict`, pre-commit; code review on every PR | Coding standard documented; SCA tool in CI |
| A.8.29 Security testing in development and acceptance | Pytest matrix on Python 3.11 + 3.12; sanitiser ruleset regression tests | Acceptance testing checklist per release |
| A.8.31 Separation of development, test, and production environments | (Deployer-side) | Environment naming and access policy |
| A.8.32 Change management | Workflow JSON in git; commit history is the change log; pre-commit gates regressions | Change advisory board for workflows touching regulated data |
| A.8.33 Test information | Test fixtures under `tests/fixtures/` ship with READMEs; no real PII in fixtures | Sanitise any deployer-side test data before committing |

## What the deployer must do

1. **Scope the ISMS**: document which workflows are in-scope, on which
   hosts, with which audit-log retention and which data classes.
2. **Maintain the Statement of Applicability (SoA)**: for each Annex A
   control, indicate whether it applies and how (Testudo + deployer
   processes + deployer infrastructure).
3. **Establish operating procedures**: change management, incident
   response, access review, sanitiser-ruleset versioning, audit-log
   monitoring.
4. **Internal audit and management review**: required by Clause 9 of
   the ISO 27001 standard. Testudo provides the technical evidence;
   the deployer's auditor reviews operating effectiveness.
5. **Engage a certification body**: an accredited registrar performs
   the Stage 1 (documentation) and Stage 2 (implementation) audits and
   issues the certificate.

## Out of scope for this document

- Annex A.6 (People) and A.7 (Physical) controls. These attach to the
  deployer's HR programme and facility security; Testudo does not
  contribute.
- Clauses 4-10 of the ISO 27001 standard itself (context, leadership,
  planning, support, operation, evaluation, improvement). The
  deployer's ISMS framework owns these.
- Vendor compliance for the cloud services a workflow binds to
  (Microsoft 365, Slack, Databricks). Each vendor publishes its own
  ISO 27001 certification; the deployer references them in the SoA.

## Related

- [SOC2-control-mapping.md](SOC2-control-mapping.md) - overlapping
  controls; many auditors run SOC 2 and ISO 27001 in parallel.
- [POSITIONING.md](../POSITIONING.md) - where ISO 27001 sits in the
  vendor-platform comparison.
- [ARCHITECTURE.md](../ARCHITECTURE.md) - the layered architecture
  that satisfies the A.8 technological controls.
