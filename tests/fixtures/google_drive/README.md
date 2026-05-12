# Google Drive test fixtures

A handful of small files for end-to-end Google Drive integration tests
once the v0.2 `fetch_drive` implementation lands. Drop them into the
Drive folder you shared with the service account (see
[`docs/GOOGLE_DRIVE_SETUP.md`](../../../docs/GOOGLE_DRIVE_SETUP.md))
and tell testudo their file IDs.

## What's in here

| File | Purpose |
|---|---|
| `sample_report.md` | Markdown with mock PII (NIN, NHS, email, postcode, SSN, IBAN, Visa, DOB). Hits every UK + several international PII patterns when sanitised. |
| `sample_employees.csv` | CSV with mock employee data: name, email, phone, postcode, department. For testing the structured-data path. |
| `sample_transactions.tsv` | TSV with mock transaction data: id, amount, iban, card, timestamp. For testing the TSV reader path. |
| `sample_workflow_drive.json` | Bundled workflow that fetches a Drive file by id, extracts text, sanitises, writes a debrief. |

## Step-by-step upload + run

### 1. Upload the fixture files

```text
1. Open drive.google.com.
2. Create a folder, e.g. "testudo-test-fixtures".
3. Right-click -> Share. Paste the service account email
   (looks like testudo-drive@<project>.iam.gserviceaccount.com).
   Permission: Viewer.
4. Drag the four files in this directory into that Drive folder.
```

### 2. Capture the file IDs

Open each file in the Drive UI. The URL looks like:

```text
https://docs.google.com/document/d/<FILE_ID>/edit
https://drive.google.com/file/d/<FILE_ID>/view
```

Copy the 33-character `<FILE_ID>` for each. Note them somewhere local
(not in this repo). You will pass these to workflows or paste them into
the Electron UI's file_id field when the v0.2 Drive picker lands.

### 3. Smoke-test the service account (optional but recommended)

Before plumbing through testudo, confirm the service account can see
the files. From the project root:

```bash
.venv/bin/python -c "
from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build
import os

creds = Credentials.from_service_account_file(
    os.environ['TESTUDO_DRIVE_CREDENTIALS'],
    scopes=['https://www.googleapis.com/auth/drive.readonly'],
)
service = build('drive', 'v3', credentials=creds)
res = service.files().list(pageSize=20, fields='files(id, name, mimeType)').execute()
for f in res.get('files', []):
    print(f['id'], f['mimeType'], f['name'])
"
```

If you see the four fixture filenames, the integration is ready. If
the list is empty, re-share the folder with the service account email
(step 3 in `docs/GOOGLE_DRIVE_SETUP.md`).

### 4. Run the bundled drive workflow (once v0.2 lands)

```bash
testudo run tests/fixtures/google_drive/sample_workflow_drive.json \
  --inputs-json <(echo '{
    "file_id": "<paste FILE_ID for sample_report.md>",
    "output_path": "runs/drive-report-debrief.md"
  }')
```

Today `connectors.google_drive` raises `NotImplementedError`. The
workflow JSON lives here so the day v0.2 ships the smoke test runs
zero-config against your shared folder.

## Privacy note

These fixtures contain **mock** PII only. The values are crafted to hit
the sanitiser's regex patterns (e.g. `AB123456C` for the UK NIN
pattern). None of the names, emails, or numbers belong to real people
or institutions. Safe to upload to a private Drive folder under your
own ownership.
