# `pdf-debrief-v015` -- Extract → sanitise → write (no LLM)

The "passive" variant of `pdf-summarise`: extract a document, sanitise
PII / cards / secrets / injection markers, write the redacted body to
disk. **No LLM call.** Use when you need the raw cleaned text rather
than a summary.

## Inputs

| Name | Required | Example | Notes |
|---|---|---|---|
| `pdf_path` | yes | `/home/jgamboa/testudo/examples/data/sample.md` | Any supported document format. |
| `output_path` | yes | `/home/jgamboa/testudo/outputs-ui/pdf-debrief-<name>.md` | Where the redacted body is written. |

## What the workflow does

```text
extract (connectors.extract_document)
   ▼
sanitise (sanitisers.pii_and_injection, redact=true)
   ▼
write_debrief (outputs.file)
   ▼
respond (outputs.chat)
```

## When to use which

- **`pdf-debrief-v015`** (this workflow): you want the redacted *full text* in your output file. No model involved, runs in ~milliseconds, no network egress.
- **`pdf-summarise-v015`**: you want a *summary* in your output file. Calls Ollama; slower; depends on the model being installed/reachable.
