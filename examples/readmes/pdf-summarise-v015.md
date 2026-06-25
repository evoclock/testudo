# `pdf-summarise-v015` -- Extract → Ollama → sanitise → write

Extract text from a document (PDF / DOCX / PPTX / HTML / JSON / TXT /
MD), ask an Ollama-served LLM to summarise, sanitise the model's
response, write the cleaned summary to disk, and return the summary
inline as the chat response.

## Prerequisites

1. Ollama daemon running locally: `ollama serve &`
2. For cloud-served models (any `<name>:cloud`): `ollama signin` once.
3. For PDF / DOCX extraction: `uv pip install -e ".[file_ops]"`.

## Inputs

| Name | Required | Example | Notes |
|---|---|---|---|
| `pdf_path` | yes | `~/testudo/examples/data/sample.md` | Local path to the document. PDF / DOCX / PPTX / HTML / JSON / TXT / MD all supported. |
| `model` | no | `minimax-m2.7:cloud` (default) | Ollama tag. Cloud-served models use `:cloud` suffix. See [OLLAMA_SETUP.md](../../docs/OLLAMA_SETUP.md) for the recommended seven. |
| `system_prompt` | no | XML-tagged role+constraints (default) | The system message sent to the model. Default constrains output to five bullet points, source-only, no speculation. |
| `output_path` | yes | `~/testudo/outputs-ui/pdf-summarise-<name>.md` | Where the redacted summary is written. |

## What the workflow does

```text
extract (connectors.extract_document)
   │  text: full extracted body, hidden-unicode + comments stripped
   ▼
summarise (models.ollama_chat)
   │  prompt: XML-wrapped task + document + output_format
   │  response: model's bullets; sanitise_output() runs inline so any
   │            secrets / PII / injection markers in the model output
   │            are caught before this step returns
   ▼
write_summary (outputs.file)
   │  redacted summary text → output_path
   ▼
respond (outputs.chat)
   text: the full summary; attachments: [output_path]
```

## Two starter examples (click in Workflow tab → Starters)

- **sample.md → minimax-m2.7:cloud** -- bundled fixture, cloud model
- **sample.md → mistral (local)** -- same fixture, local 7B model

## Common failures

| Error | Cause |
|---|---|
| `404 Not Found` on `/api/chat` | Model name doesn't match anything in `ollama list`. Cloud-served models need `:cloud` suffix. |
| `Missing key 'X' in reference 'inputs.X'` | Workflow input has no default and you didn't supply it. The bridge applies defaults automatically when there is one. |
| Summary contains `${steps.extract.content}` literal | Older orchestrator that didn't support string interpolation; pull latest commits. |
