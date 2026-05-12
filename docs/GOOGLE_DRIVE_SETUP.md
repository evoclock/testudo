---
title: "Google Drive setup for the connectors.google_drive tool"
---

The `connectors.google_drive` orchestrator tool is a v0.2 placeholder in
v0.1.5. This document covers what you need to provision on Google's side
before the live implementation lands, so once it does you can drop in
credentials without touching code.

## Choose service-account, not OAuth user-consent

Two paths in Google's API world:

- **OAuth user-consent flow.** A browser-redirect dance that produces a
  refresh token tied to a real Google account. Right for end-user tools
  where the user wants to access *their own* Drive. Wrong for
  long-running automation: refresh tokens expire if unused, consent
  screens have to be reverified periodically, and the redirect URI has
  to match what's registered in Cloud Console.
- **Service account.** A bot identity with its own email. Acts like a
  separate user that you grant access to specific Drive folders or
  files. The JSON key never expires and the auth flow is one
  `oauth2.service_account.Credentials.from_service_account_file(...)`
  call.

Testudo uses the service-account path. It is the right shape for a
local agent runtime that needs to ingest files from a known Drive
location during a workflow run.

## One-time setup

### 1. Create a Google Cloud project

1. Open [console.cloud.google.com](https://console.cloud.google.com/).
2. Click the project picker at the top, then "New project".
3. Name it something like "testudo-runtime". Org and location defaults
   are fine.

### 2. Enable the Drive API

1. With the new project selected, go to "APIs & Services" -> "Library".
2. Search "Google Drive API".
3. Click it, then "Enable".

### 3. Create a service account

1. "APIs & Services" -> "Credentials" -> "Create credentials" -> "Service
   account".
2. Service account name: `testudo-drive`. Skip the optional roles step;
   we are not granting GCP-level IAM here.
3. After creation, copy the service account's email address. It will
   look like `testudo-drive@<project-id>.iam.gserviceaccount.com`. This
   is the address you will share Drive folders / files with.

### 4. Create and download a JSON key

1. On the service account's detail page, "Keys" tab -> "Add key" ->
   "Create new key" -> "JSON".
2. The browser downloads a JSON file. Save it somewhere outside the
   testudo repo (the repo is OSS and you do not want this file
   committed by accident). A common location:
   `~/.config/testudo/drive-service-account.json`.
3. Set the file's permissions to `600`:

   ```bash
   chmod 600 ~/.config/testudo/drive-service-account.json
   ```

### 5. Share the target Drive folder(s) with the service account

The service account does not automatically see anything in your Drive.
For each folder or file you want testudo to read:

1. Open the folder in [drive.google.com](https://drive.google.com/).
2. Right-click -> "Share".
3. Paste the service account email (the one ending in
   `iam.gserviceaccount.com`).
4. Pick "Viewer" (read-only) for most cases. Use "Editor" only if a
   future workflow needs to write into the folder.

You can repeat step 5 for as many folders as you want. The service
account behaves like a separate user that you grant access to
specifically.

## Tell testudo about the credentials

When the v0.2 implementation lands, two environment variables wire it up:

```bash
export TESTUDO_DRIVE_CREDENTIALS="$HOME/.config/testudo/drive-service-account.json"
export TESTUDO_DRIVE_SCOPES="https://www.googleapis.com/auth/drive.readonly"
```

Then install the optional dependency:

```bash
uv pip install -e ".[drive]"   # extra will be added in v0.2; today it lives behind a placeholder
```

The connector tool signature is already wired (see
`src/testudo/connectors/tools.py`):

```python
@register_tool("connectors.google_drive")
def google_drive_tool(_ctx, *, file_id: str, credentials: dict | None = None):
    return fetch_drive(file_id, credentials=credentials).to_dict()
```

`fetch_drive` is a `NotImplementedError` placeholder in v0.1.5. When the
v0.2 implementation lands it will use the service-account JSON file's
contents (loaded once at process start), call
`drive.files().get_media(fileId=file_id)`, and return a `StagedInput`
matching the local-file and HTTPS connectors.

## Finding a file ID

A Drive file URL looks like:

```text
https://docs.google.com/document/d/<FILE_ID>/edit
https://drive.google.com/file/d/<FILE_ID>/view
```

The 33-character string between `/d/` and the next `/` is the file ID.
Pass that as the `file_id` input to the `connectors.google_drive` tool
or workflow step.

## Verifying access (before v0.2 ships)

You can confirm the service account can see your folder without testudo
in the loop. Quick Python smoke test:

```bash
uv pip install google-api-python-client google-auth
```

```python
from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build

creds = Credentials.from_service_account_file(
    "/home/you/.config/testudo/drive-service-account.json",
    scopes=["https://www.googleapis.com/auth/drive.readonly"],
)
service = build("drive", "v3", credentials=creds)
results = service.files().list(pageSize=10, fields="files(id, name)").execute()
for f in results.get("files", []):
    print(f["id"], f["name"])
```

If you see filenames from your shared folder, the service account is
correctly provisioned and ready for testudo's v0.2 implementation.

## Security notes

- **Never commit the service-account JSON to a repo.** Add the path to
  your shell's `.env` or systemd environment file, not to source.
- **Use the narrowest scope you can.** `drive.readonly` is enough for
  ingest workflows. `drive` (full read-write) is rarely needed.
- **Audit which folders the service account can see.** A compromised
  testudo process inherits whatever the service account has access to.
  Grant access folder by folder, not at the Drive root.
- **Rotate the JSON key periodically.** Cloud Console -> Service
  accounts -> Keys -> "Add key" gives you a new one; delete the old key
  after you have copied the new file into place.

## Databricks (separate doc, coming)

Databricks setup is parallel in shape: PAT or service-principal,
workspace + warehouse identifiers, optional VPC settings. Documented
separately once the live integration test is in place. For v0.1.5 the
adapter supports PAT auth via the `[databricks]` extra; the env vars
the v0.1.5 code reads are `DATABRICKS_SERVER_HOSTNAME`,
`DATABRICKS_HTTP_PATH`, `DATABRICKS_TOKEN`.
