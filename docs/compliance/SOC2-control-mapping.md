---
title: "Testudo SOC 2 Type II control mapping"
status: draft
last_updated: 2026-05-13
---

## Status

**Draft scaffold.** This document is part of the v0.1.7 milestone and
will be completed alongside the Microsoft 365 + Slack connector work
(see [../ROADMAP.md](../ROADMAP.md)). The structure and the
Testudo-side feature mapping are in place; the deployer-side evidence
requirements will be filled in as the v0.1.7 work lands.

## Scope and audience

This document is for a deployer's compliance team who needs to map
Testudo features to the AICPA Trust Services Criteria for a SOC 2
Type II audit.

**Important framing**: Testudo is a runtime that a deployer installs,
configures, and operates. SOC 2 attaches to service-providing
organisations, not to runtimes. The deployer is the certifiable
entity; Testudo features are the technical controls the deployer can
point at during the audit. The auditor evaluates the deployer's
operating effectiveness, not Testudo's code.

The five Trust Services Criteria (TSC) are: Security, Availability,
Processing Integrity, Confidentiality, Privacy. The mapping below
addresses each.

## Trust Services Criteria mapping

### Security (CC - Common Criteria)

| TSC reference | Testudo feature | Evidence the deployer collects |
|---|---|---|
| CC6.1 Logical access controls | `Permissions` model (filesystem read/write prefixes, network egress allow-list, process spawn deny-by-default), bearer-token auth on the FastAPI bridge | Workflow JSON definitions in git; bearer-token rotation policy |
| CC6.6 Boundary protection | Container isolation per workflow via `IsolationProfile`; egress allow-list enforced at the container's iptables layer (v0.1.6) | Per-workflow `IsolationProfile` declarations; iptables ruleset captured per run |
| CC6.7 Data transmission integrity | HMAC-SHA256 signed receipts between read-only LLM capturer and write-only file writer; bearer-token + TLS on the bridge | Receipt-key rotation logs; bridge TLS termination evidence |
| CC6.8 Malicious code prevention | In-house `AgentScanner` + scan-before-permit gate; Socket Firewall on every package install (operator-side discipline) | Scan-rejected audit events; sfw scan logs |
| CC7.1 Vulnerability management | `npm audit`, `pip-audit`, dependabot equivalents; pre-commit hook prevents format / type regressions reaching CI | CI run history; dependency advisory triage record |
| CC7.2 Monitoring of controls | Per-run JSONL audit log; all permission decisions, sanitiser verdicts, and errors recorded | Audit log retention policy; SIEM forwarder configuration |

### Availability (A)

| TSC reference | Testudo feature | Evidence the deployer collects |
|---|---|---|
| A1.1 Capacity planning | In-house token-bucket rate limiter on the bridge; per-bearer-token keying | Rate-limit configuration documented; capacity-test results |
| A1.2 System availability monitoring | `GET /health` endpoint; per-run audit log captures workflow start / step / end / error | Uptime monitoring tied to `/health`; incident response runbook |
| A1.3 Recovery procedures | Workflow definitions in git: a failed runtime can be rebuilt from the workflow JSON + the input data; nothing of value lives only on a running container | Backup and restore procedure for input data and audit logs |

### Processing Integrity (PI)

| TSC reference | Testudo feature | Evidence the deployer collects |
|---|---|---|
| PI1.1 Inputs processed completely / accurately | Sanitiser pipeline runs on every byte of input; `Permissions` model rejects out-of-scope inputs at the workflow boundary | Sanitiser test corpus + 316 unit tests; per-run audit log of accept / redact / reject decisions |
| PI1.2 Authorised inputs | Bearer-token auth on the bridge; `permissions.network.egress` allow-list rejects unauthorised destinations | Bearer-token issuance log; per-run permission-denial audit events |
| PI1.3 Processing accuracy | HMAC-signed receipts ensure that what an LLM emits is exactly what reaches a write-side MCP server | Receipt verification audit events; tamper-detection test results |
| PI1.4 Output completeness | Audit log records `step_start` and `step_end` for every step; orphaned `step_start` without a matching `step_end` is detectable | Audit-log integrity check; per-step completion rate |

### Confidentiality (C)

| TSC reference | Testudo feature | Evidence the deployer collects |
|---|---|---|
| C1.1 Confidential data identification | Sanitiser pipeline identifies PII (UK + ~50 country patterns), secrets (Hillstar parity + extras), hidden unicode, prompt-injection markers, OWASP web + MCP threat markers | Sanitiser ruleset version; finding categorisation matrix |
| C1.2 Disposal of confidential data | Per-run audit logs are append-only JSONL; deployer's log retention policy governs disposal | Log retention configuration; secure-deletion policy for outputs |

### Privacy (P)

| TSC reference | Testudo feature | Evidence the deployer collects |
|---|---|---|
| P1.1 Notice to data subjects | (Deployer responsibility) | Privacy policy referencing Testudo's role in processing |
| P3.1 Choice and consent | (Deployer responsibility) | Consent capture mechanism at the data-collection step (upstream of Testudo) |
| P4.1 Collection of personal data | Sanitiser output-side pipeline ensures personal data is redacted before leaving Testudo's processing boundary unless explicitly authorised | Per-run audit log of redaction decisions |
| P6.1 Disclosure of personal data | Per-workflow `permissions.network.egress` allow-list bounds where data can go | `IsolationProfile` declarations per workflow |

## What the deployer must do

Testudo provides the technical controls; the deployer assembles them
into an audit-ready posture:

1. **Document the deployment**: which workflows run, on which hosts,
   for which data classes, with which audit-log retention.
2. **Establish operating policies**: workflow-change approval, bearer-
   token rotation cadence, HMAC receipt-key rotation cadence,
   sanitiser-ruleset version pinning per release.
3. **Run the controls continuously**: monitor `/health`, ship audit
   logs to a SIEM, alert on permission-denied events.
4. **Engage the auditor**: provide the auditor with workflow
   definitions (git refs), audit-log samples, sanitiser ruleset
   evidence, and the operating policies. Tools like Drata, Vanta, or
   Secureframe automate evidence collection but the human auditor is
   non-negotiable.

## Out of scope for this document

- The auditor's process itself (control testing procedures, sample
  selection, deficiency reporting). Engage a SOC 2 Type II auditor
  directly.
- Compliance for the inputs to Testudo (the upstream data collection,
  consent, lawful basis). Those attach to the deployer's broader
  programme.
- Microsoft / Slack / Databricks compliance. Each vendor publishes
  its own SOC 2 reports; the deployer references them alongside this
  one when describing the end-to-end data flow.

## Related

- [POSITIONING.md](../POSITIONING.md) - where SOC 2 sits in Testudo's
  positioning vs vendor agent platforms.
- [ARCHITECTURE.md](../ARCHITECTURE.md) - the layers (sanitiser,
  permission, audit) that each Trust Services Criterion maps to.
- [../../STATUS.md](../../STATUS.md) - current test count and lint
  posture; the auditor will want a current snapshot.
