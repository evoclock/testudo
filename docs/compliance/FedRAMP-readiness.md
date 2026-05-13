---
title: "Testudo FedRAMP readiness statement"
status: draft
last_updated: 2026-05-13
---

## Status

**Draft scaffold.** Part of the v0.1.7 milestone (see
[../ROADMAP.md](../ROADMAP.md)). The structure and the Testudo-side
feature mapping are in place; deployer-side requirements will be filled
in as v0.1.7 lands.

This is a **readiness statement**, not a FedRAMP authorisation.
Testudo itself cannot be FedRAMP-authorised because authorisation
attaches to a Cloud Service Offering (CSO) operated by a Cloud Service
Provider (CSP), not to a runtime that customers self-deploy. A
deployer pursuing FedRAMP authorisation for a CSO that includes
Testudo would use this document to map Testudo features to NIST
SP 800-53 controls.

## Scope and audience

This document is for a deployer's compliance team pursuing FedRAMP
authorisation at the Low, Moderate, or High impact level for a CSO
that uses Testudo as a runtime component.

## Authorisation paths

FedRAMP has three impact levels mapped to FIPS 199 categorisations:

- **Low**: confidentiality, integrity, availability impacts are all
  Low. Public-facing data, minimal sensitivity. ~125 NIST 800-53
  controls.
- **Moderate**: any of C/I/A is Moderate. Most commercial federal
  workloads. ~325 controls.
- **High**: any of C/I/A is High. Law enforcement, emergency services,
  some health data. ~425 controls.

Testudo features map most cleanly to Moderate. High-impact deployments
require additional controls (HSM-backed key management, FIPS 140-2
validated cryptographic modules, dual authorisation for sensitive
operations) that the deployer adds at the infrastructure layer.

## Required infrastructure

A FedRAMP-authorised CSO using Testudo must be deployed on
FedRAMP-authorised hosting:

- **Azure Government** (FedRAMP High authorisation)
- **AWS GovCloud (US)** (FedRAMP High authorisation)
- **Google Cloud Assured Workloads** (FedRAMP High authorisation)
- **Oracle Cloud for Government** (FedRAMP High authorisation)

Self-hosted on-prem deployments can pursue FedRAMP authorisation but
the path is significantly more complex; consult a 3PAO (Third Party
Assessment Organisation) early.

## NIST SP 800-53 control families - Testudo coverage

The mapping focuses on the families Testudo directly contributes to.
The deployer maps the remainder (AT, CP, IR, MA, PE, PL, PS, SA, SR)
to their broader infrastructure and operations programme.

### AC (Access Control)

| Control | Testudo feature |
|---|---|
| AC-2 Account management | Bearer-token auth on the bridge; per-bearer-token rate limiter keying |
| AC-3 Access enforcement | `Permissions` model (filesystem prefixes, network egress allow-list, process spawn deny-by-default) |
| AC-4 Information flow enforcement | Per-workflow egress allow-list enforced at iptables (v0.1.6); read-only / write-only MCP server separation with HMAC receipts |
| AC-6 Least privilege | Deny-by-default permissions; per-workflow declarations; scan-before-permit gate for MCP-config / skill artifacts |
| AC-17 Remote access | Bridge binds 127.0.0.1; remote access via the deployer's identity provider over TLS |

### AU (Audit and Accountability)

| Control | Testudo feature |
|---|---|
| AU-2 Event logging | Per-run JSONL audit log: workflow_start, step_start, step_end, permission_*, error |
| AU-3 Content of audit records | Audit records include timestamp (UTC ISO 8601), event type, workflow / step identifiers, decision outcomes, error details |
| AU-4 Audit log storage capacity | Append-only JSONL; deployer's retention policy governs |
| AU-6 Audit record review | Audit logs feed an external SIEM via log shipping |
| AU-9 Protection of audit information | Audit logs are write-only from the workflow's perspective; tamper detection at the SIEM layer |
| AU-12 Audit generation | Generated for every workflow run; no opt-out |

### CM (Configuration Management)

| Control | Testudo feature |
|---|---|
| CM-2 Baseline configuration | Workflow definitions and `IsolationProfile` declarations in git; the commit SHA is the configuration baseline |
| CM-3 Configuration change control | Git PR workflow; pre-commit hook enforces ruff format + ruff check + mypy + detect-private-key |
| CM-6 Configuration settings | Pre-commit config + pyproject.toml + tsconfig.json codify the security-relevant settings |
| CM-7 Least functionality | Per-workflow `Permissions` model removes capabilities the workflow does not declare needing |
| CM-8 System component inventory | Dependencies in `uv.lock`, `package-lock.json`, `pyproject.toml`; pre-audited via `npm audit`, `pip-audit` |

### IA (Identification and Authentication)

| Control | Testudo feature |
|---|---|
| IA-2 User identification and authentication | Bearer-token auth on the bridge; v0.1.7 adds MSAL device-code flow for per-user attribution |
| IA-5 Authenticator management | Token cache file (`~/.config/testudo/tokens/`); proactive refresh before expiry; deployer rotates per policy |
| IA-9 Service identification and authentication | v0.1.7 MSAL client-credentials flow uses Entra ID service principal; mTLS at the deployer's ingress |

### SC (System and Communications Protection)

| Control | Testudo feature |
|---|---|
| SC-7 Boundary protection | Container `IsolationProfile` with declared egress; iptables enforcement (v0.1.6) |
| SC-8 Transmission confidentiality / integrity | HMAC-SHA256 receipts between MCP servers; TLS on the bridge |
| SC-12 Cryptographic key establishment / management | HMAC receipt key stored per-deployer; rotation per policy |
| SC-13 Cryptographic protection | SHA-256 (FIPS 140-2 approved); TLS via the deployer's chosen termination |
| SC-23 Session authenticity | Bearer token per session; rate limiter blocks brute force |
| SC-39 Process isolation | Container per workflow; separate user namespace; tmpfs `/tmp` |

### SI (System and Information Integrity)

| Control | Testudo feature |
|---|---|
| SI-2 Flaw remediation | Pre-commit hook + CI matrix; dependency advisories triaged through `npm audit` / `pip-audit` |
| SI-3 Malicious code protection | AgentScanner + scan-before-permit gate; Socket Firewall install discipline; sanitiser pipeline detects prompt-injection chains |
| SI-4 System monitoring | Per-run audit log + SIEM forwarder |
| SI-7 Software, firmware, and information integrity | HMAC-signed receipts ensure LLM output integrity in transit; reproducible builds via `uv.lock` / `package-lock.json` |
| SI-10 Information input validation | Sanitiser input-side pipeline on every byte; permissions enforce input source allow-list |
| SI-11 Error handling | Structured error events in the audit log; no PII / secrets in error messages (sanitiser runs before logging) |
| SI-12 Information management and retention | Append-only audit log; deployer retention policy |

## FIPS 140-2 cryptographic posture

Testudo's cryptography:

- **HMAC-SHA256** for receipts (FIPS 140-2 approved hash family).
- **TLS** on the bridge (FIPS-validated cipher suites available when
  the deployer uses a FIPS-validated build of OpenSSL or Python).
- **Random tokens** via `secrets.token_urlsafe()` (uses `os.urandom`,
  FIPS-acceptable on FIPS-validated platforms).

For FedRAMP High deployments requiring FIPS-validated cryptographic
modules end-to-end, the deployer must:

- Use a FIPS-validated Python build (e.g. RHEL UBI FIPS image).
- Use a FIPS-validated container runtime.
- Document the FIPS validation certificates in the System Security
  Plan (SSP).

## Supply-chain controls

NIST 800-53 SR (Supply Chain Risk Management) family:

- **SLSA build provenance**: v0.3 roadmap item. In the interim,
  signed git tags, reproducible builds via `uv.lock`, pre-commit hook
  enforcement.
- **Socket Firewall on every install**: documented in the README and
  enforced by the user-level PreToolUse hook.
- **Dependency pinning**: `package-lock.json`, `uv.lock` committed.
- **Code review on every PR**: pre-commit gate + GitHub branch
  protection (deployer enforces).

## What the deployer must do

1. **Pursue an authorisation path**: Joint Authorisation Board (JAB)
   for High-impact CSOs, Agency authorisation for Moderate or single-
   agency Low. Engage a 3PAO assessor early.
2. **Author the System Security Plan (SSP)**: ~1000 page document
   mapping every applicable NIST 800-53 control to the CSO's
   implementation. This document is a starting input for the SSP's
   Testudo-relevant sections.
3. **Stand up FedRAMP-authorised hosting** (Azure Gov, AWS GovCloud,
   etc.) and inherit the hosting CSP's authorisation for the
   infrastructure controls (CP, MA, PE).
4. **Continuous monitoring**: per FedRAMP requirements, includes
   weekly vulnerability scans, monthly POA&M updates, annual
   re-authorisation.
5. **Realistic timeline**: 12-18 months from "start the SSP" to
   "Authority to Operate (ATO) issued". Testudo's documentation work
   here can be a few weeks; the deployer's certification effort is the
   bulk.

## Out of scope for this document

- The full SSP. The deployer authors it; this document is one input.
- Hosting-CSP controls. These are inherited from Azure Gov / AWS
  GovCloud / etc.
- Continuous monitoring tooling. The deployer chooses (Wiz, Lacework,
  Prisma Cloud, Tenable, etc.).
- Personnel controls (PS family). The deployer's HR programme.

## Related

- [SOC2-control-mapping.md](SOC2-control-mapping.md) - overlapping
  control coverage.
- [ISO27001-Annex-A-mapping.md](ISO27001-Annex-A-mapping.md) - Annex
  A controls often satisfy NIST 800-53 controls and vice versa; the
  deployer can reuse evidence across frameworks.
- [POSITIONING.md](../POSITIONING.md) - the vendor-platform
  alternative paths (Microsoft Azure Government, AWS Bedrock with
  FedRAMP).
