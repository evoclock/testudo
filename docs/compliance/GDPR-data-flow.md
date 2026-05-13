---
title: "Testudo GDPR compliance and data flow"
status: draft
last_updated: 2026-05-13
---

## Status

**Draft scaffold.** Part of the v0.1.7 milestone (see
[../ROADMAP.md](../ROADMAP.md)). The structure and the Testudo-side
feature mapping are in place; deployer-side per-workflow data-flow
declarations will be filled in as v0.1.7 lands and as workflows are
authored.

## Scope and audience

This document is for a deployer's data protection officer (DPO) or
privacy team who needs to demonstrate compliance with the EU General
Data Protection Regulation (GDPR) and its UK counterpart (UK GDPR),
specifically the data-residency requirements and the data-flow
documentation requirements.

GDPR is **not a certification**. There is no formal "GDPR certificate"
that a product or organisation can hold. Compliance is demonstrable,
not certifiable. Article 30 of GDPR requires data controllers and
processors to maintain records of processing activities (RoPA); this
document supports the RoPA for any deployment of Testudo.

## Controller / processor framing

In a typical deployment:

- The **deployer's organisation** is the data controller for personal
  data flowing into Testudo workflows.
- **Testudo** is software the deployer operates; it is not itself a
  processor in the GDPR sense (there is no service-provider
  relationship between Testudo's authors and the deployer).
- **Cloud services Testudo binds to** (Microsoft 365 for Teams /
  SharePoint, Slack, Databricks, Ollama Cloud) are sub-processors.
  The deployer's DPA with each vendor governs.

## GDPR principles mapping (Article 5)

| Principle | Testudo feature | Deployer responsibility |
|---|---|---|
| (1)(a) Lawfulness, fairness, transparency | (Deployer-side: lawful basis, privacy notice) | Article 13/14 notices to data subjects |
| (1)(b) Purpose limitation | Per-workflow `permissions` declarations bound the processing scope; sanitiser pipeline enforces the boundary | Document the purpose of each workflow in its README |
| (1)(c) Data minimisation | Sanitiser output-side pipeline redacts non-essential PII before egress; per-workflow allow-list constrains what data can flow where | Author workflows that pull only the data needed for the purpose |
| (1)(d) Accuracy | (Deployer-side: input validation, source of truth, rectification mechanism) | Rectification procedure for data subjects |
| (1)(e) Storage limitation | Per-run audit log retention is deployer-governed; workflow outputs are written to declared paths | Retention policy per data class; deletion procedure |
| (1)(f) Integrity and confidentiality | Container isolation per workflow; HMAC-signed receipts between MCP servers; sanitiser pipeline catches accidental disclosure | TLS termination, at-rest encryption on the host |
| (2) Accountability | Per-run audit log + sanitiser test corpus (316 tests) + workflow definitions in git = an evidence trail | RoPA, DPIA per high-risk workflow |

## Data residency

GDPR Article 44-49 governs international data transfers. Two-question
framing:

1. **Where is the personal data stored?** The deployer's hosts plus
   any vendor sub-processor the workflow binds to.
2. **Where is it processed?** Same.

Testudo's contributions:

- **Local-first runtime**: by default, data does not leave the host
  unless a connector wires it elsewhere. Local Ollama models stay on
  the host. DuckDB is local. Workflow JSON, audit logs, and outputs
  are local files.
- **Per-workflow data-flow declaration**: each workflow's README
  enumerates which connectors are used, which destinations data
  reaches, and which residency region is required. v0.1.7 adds a
  `data_residency:` field to the `IsolationProfile` so the runtime
  enforces the declaration at the connector layer.
- **Connector binding to vendor-tenant regions**: Microsoft Graph
  honours tenant data residency (EU tenants stay in EU data centres).
  The deployer's Microsoft 365 tenant geography carries through.

### Known data-residency gotchas

- **Ollama Cloud (`:cloud` suffix models)**: routes through Ollama's
  hosted infrastructure, **not** guaranteed EU-resident. For strict
  EU/UK deployments, use local-only Ollama models (any model without
  the `:cloud` suffix). Documented in
  [../OLLAMA_SETUP.md](../OLLAMA_SETUP.md).
- **Anthropic / OpenAI / Google adapters (v0.2)**: vendor data
  residency depends on the deployer's chosen API endpoint
  (`api.anthropic.com` vs Azure-hosted Anthropic, etc.). The deployer
  picks the endpoint in the workflow JSON.
- **Slack**: data residency depends on the Slack workspace's
  configured region (Slack EDS).
- **Databricks**: data residency depends on the workspace's region.
  The deployer picks the workspace.

## Data-flow declaration per workflow

Each shipped workflow includes a `examples/readmes/<name>.md` that
lists:

- **Inputs**: what data the workflow ingests and from where.
- **Processing steps**: each step in the workflow chain and what it
  does to the data.
- **Outputs**: what leaves the workflow boundary and to where.
- **Data classes**: which categories of personal data may appear in
  the data flow (named individuals, contact info, identifiers).
- **Lawful basis**: deployer-filled section noting the lawful basis
  for processing each data class.

The v0.1.7 work formalises this template so every workflow's README
follows it.

## Data subject rights (Articles 15-22)

GDPR grants data subjects rights to access, rectification, erasure,
restriction, portability, and objection. Testudo's contribution:

| Right | Testudo feature |
|---|---|
| Article 15 Access | Audit log is queryable JSONL; the deployer can extract all processing events relating to a given identifier |
| Article 16 Rectification | (Deployer-side; depends on source-of-truth system) |
| Article 17 Erasure | Append-only audit log + workflow outputs at declared paths = the deletion surface is enumerable |
| Article 18 Restriction | Per-workflow `permissions` can be edited and the workflow paused (deployer's workflow management) |
| Article 20 Portability | (Deployer-side; depends on source-of-truth system) |
| Article 21 Objection | (Deployer-side; depends on the lawful basis) |

## Records of Processing Activities (Article 30)

The RoPA template for a Testudo-using deployment, per workflow:

- Name and contact of the controller / DPO.
- Purpose of the processing (from the workflow's README).
- Categories of data subjects (from the workflow's README).
- Categories of personal data (from the sanitiser ruleset + workflow
  inputs).
- Categories of recipients (from the workflow's
  `permissions.network.egress` + connector list).
- International transfers (if any vendor sub-processor is non-EU).
- Time limits for erasure (deployer's retention policy).
- General description of technical and organisational security
  measures (from this document + the SOC 2 / ISO 27001 mapping).

## Data Protection Impact Assessment (Article 35)

A DPIA is required when processing is likely to result in high risk
to data subjects. Triggers include: large-scale processing of
special-category data, profiling, monitoring of public areas.

For Testudo workflows touching high-risk categories, the DPIA
includes:

- The workflow's purpose, scope, and necessity.
- Risks to data subjects (specifically: sanitiser false-negatives,
  prompt-injection chains producing unauthorised disclosures, model
  hallucinations producing inaccurate personal data).
- Measures to address the risks: defence-in-depth sanitiser pipeline,
  per-workflow permissions, audit log review, model-output
  verification.
- Consultation with the DPO and (if required) with the supervisory
  authority.

## What the deployer must do

1. **Establish lawful basis** for each workflow's processing
   (Article 6, plus Article 9 if special-category data is involved).
2. **Author privacy notices** to data subjects (Articles 13-14).
3. **Maintain the RoPA** (Article 30) per workflow.
4. **Run DPIAs** for high-risk workflows (Article 35).
5. **Negotiate DPAs** with each vendor sub-processor (Articles 28).
6. **Document data-flow declarations** in each workflow's README.
7. **Configure retention** per data class.
8. **Operate the rights-request procedure** (Articles 15-22).
9. **Designate a DPO** if required (Article 37).
10. **Notify breaches** within 72 hours where applicable (Article 33).

## Out of scope for this document

- The deployer's broader privacy programme. Testudo is one technical
  control among many.
- Lawful basis determination. The deployer's DPO owns this per
  workflow.
- Cross-border transfer mechanisms (Standard Contractual Clauses,
  adequacy decisions, Binding Corporate Rules). The deployer's legal
  team owns these.
- Industry-specific GDPR-adjacent rules (HIPAA in the US is a
  separate framework; UK has DPA 2018 supplementing UK GDPR).

## Related

- [SOC2-control-mapping.md](SOC2-control-mapping.md) - the Privacy
  TSC overlaps with several GDPR principles.
- [ISO27001-Annex-A-mapping.md](ISO27001-Annex-A-mapping.md) - A.5
  and A.8 controls overlap with Article 32 security requirements.
- [POSITIONING.md](../POSITIONING.md) - GDPR data-residency framing
  in the vendor-platform comparison.
- [../OLLAMA_SETUP.md](../OLLAMA_SETUP.md) - the `:cloud` suffix
  caveat for GDPR-strict environments.
