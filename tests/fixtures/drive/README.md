# Drive test fixtures

Three small files to upload to a Google Drive folder for end-to-end
testing of testudo's URL mode (which works against any public HTTPS
URL, Drive being one source).

## What to upload

| File | Tests |
|---|---|
| `sample_report.md` | UK PII patterns: NIN, NHS, postcode, phone, DOB, email. Plus US SSN, IBAN, Visa. |
| `sample_log.txt` | Prompt-injection markers + leaked secrets (Anthropic API key, AWS key, Bearer token). |
| `sample_customers.csv` | Structured rows with PII columns; exercises the sanitiser on tabular text. |

Three files is enough; each one hits a different sanitiser pass.

## Upload + share + grab the URL

Per file:

1. **drive.google.com** → drag the file into a folder of your choice.
2. Right-click the uploaded file → **Share**.
3. Under "General access", switch from "Restricted" to **"Anyone with the link"**. Role: **Viewer**.
4. Click **Copy link**. You'll get something like:
   ```text
   https://drive.google.com/file/d/1AbCdEfGhIjKlMnOpQrStUvWxYz12345/view?usp=sharing
   ```
5. Pull out the 33-character file ID (the bit between `/d/` and `/view`). For testudo, rewrite the link as:
   ```text
   https://drive.google.com/uc?export=download&id=1AbCdEfGhIjKlMnOpQrStUvWxYz12345
   ```
   That's the form `connectors.https_get` can fetch from anonymously.

## Run it from the UI

1. Bring up the bridge + Electron app (see project README).
2. Click the **URL** tab.
3. Paste the rewritten direct-download URL.
4. Output path: anything writable, e.g. `/tmp/testudo-drive-report.md`.
5. Click **Fetch and sanitise**.

Right-side activity panel should show:

- `url-fetch completed` badge
- A row of severity-coloured finding counts (high / critical for `sample_report.md`)
- The audit log path under it

The output file at the path you chose will contain the sanitised body
with PII replaced by `[REDACTED-*]` markers.

## Run it from the CLI

Same effect, no UI:

```bash
testudo run examples/workflow-url-fetch.json \
  --inputs-json <(echo '{
    "url": "https://drive.google.com/uc?export=download&id=<PASTE-FILE-ID>",
    "output_path": "/tmp/testudo-drive-report.md",
    "max_bytes": 10485760
  }')
```

## Constraints to know

- **File must be under ~25 MB.** Google interposes a virus-scan
  confirmation page for larger anonymous downloads; `https_get`
  won't dance through it.
- **Link-share must be "Anyone with the link".** "Restricted" or
  domain-only sharing will return an HTML login page (which the
  sanitiser will then refuse as injection-heavy garbage).
- **Plain text formats only on this path.** Markdown, txt, html, csv,
  tsv, json all round-trip cleanly. For PDFs / DOCX over a URL, today
  you have to download locally first and use the File tab; the
  fetch-then-extract workflow is a v0.1.6 addition.
