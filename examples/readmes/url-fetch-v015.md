# `url-fetch-v015` -- HTTPS GET → sanitise → write

Fetch a text-shaped resource over HTTPS, sanitise the response body
for PII / cards / secrets / injection markers, write the redacted
content to disk, and return a chat-inline summary.

## Prerequisites

None for public URLs. For Google Drive single-file URLs the share
state must be **Anyone with the link**; folder URLs are not supported
(this workflow fetches one resource at a time).

## Inputs

| Name | Required | Example | Notes |
|---|---|---|---|
| `url` | yes | `https://raw.githubusercontent.com/.../README.md` | Any HTTPS URL returning text. Drive `/file/d/<ID>/view` URLs auto-rewrite to `/uc?export=download&id=<ID>` in the UI's URL tab. |
| `output_path` | yes | `~/testudo/outputs-ui/url-fetch-readme.md` | Where the redacted body is written. |
| `max_bytes` | no | `10485760` (default 10 MiB) | Hard cap on response size to prevent runaway memory use. |

## What the workflow does

```text
fetch (connectors.https_get)
   │  text body, follows redirects, accepts text/* +
   │  application/{json,yaml,x-yaml,octet-stream}
   ▼
sanitise (sanitisers.pii_and_injection, redact=true)
   │  PII / cards / secrets replaced with [REDACTED-<label>];
   │  injection markers cause reject
   ▼
write_summary (outputs.file)
   ▼
respond (outputs.chat)
```

## Common failures

| Error | Cause |
|---|---|
| `Disallowed content type 'image/...'` | Body is binary (image, video). This workflow only handles text. |
| `HTTPStatusError: 302 Found` | We follow redirects; if you see this it's a chain that exceeded the limit or a non-HTTPS redirect target. |
| `HTTPStatusError: 401 Unauthorized` | URL requires auth (not link-shared Drive, internal site, etc.). |
| `ValueError: Response too large` | Body exceeds `max_bytes`. Raise the cap or pick a smaller resource. |
