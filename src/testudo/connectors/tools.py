"""
Module: testudo.connectors.tools

Purpose: register connector functions as orchestrator tools so workflow steps
can reference them by name. Side effect of importing this module: every tool
below appears in the orchestrator's ``DEFAULT_REGISTRY``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from testudo.connectors.extract import EXTRACTORS, extract_document
from testudo.connectors.https import fetch_https
from testudo.connectors.local import fetch_local
from testudo.orchestrator.context import StepContext
from testudo.orchestrator.registry import register_tool
from testudo.sanitisers.unicode_payload import strip_hidden


@register_tool("connectors.local_file")
def local_file_tool(
    _ctx: StepContext,
    *,
    path: str,
    max_bytes: int = 10 * 1024 * 1024,
) -> dict[str, Any]:
    """Read a local file and return a StagedInput dict."""
    return fetch_local(Path(path), max_bytes=max_bytes).to_dict()


@register_tool("connectors.https_get")
def https_get_tool(
    _ctx: StepContext,
    *,
    url: str,
    max_bytes: int = 10 * 1024 * 1024,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Fetch an HTTPS URL and return a StagedInput dict.

    For public link-shared Google Drive files, use the direct-download
    form: ``https://drive.google.com/uc?export=download&id=<FILE_ID>``.
    Private Drive files require authentication and are out of scope.
    """
    return fetch_https(url, max_bytes=max_bytes, timeout=timeout).to_dict()


@register_tool("connectors.extract_document")
def extract_document_tool(
    _ctx: StepContext,
    *,
    path: str,
    strip_hidden_payloads: bool = True,
) -> dict[str, Any]:
    """Extract text from a document (PDF / DOCX / PPTX / HTML / JSON / TXT).

    Dispatch on suffix via the shared ``EXTRACTORS`` table. With
    ``strip_hidden_payloads=True`` (default) the extracted text is run
    through ``strip_hidden`` before return so zero-width characters, bidi
    overrides, HTML comments, and base64 blobs are removed at the
    extraction boundary.
    """
    target = Path(path)
    if not target.is_file():
        raise FileNotFoundError(path)
    if target.suffix.lower() not in EXTRACTORS:
        raise ValueError(f"Unsupported document format: {target.suffix or '(no suffix)'}")

    fmt, raw_text = extract_document(target)

    if strip_hidden_payloads:
        cleaned, findings = strip_hidden(raw_text)
    else:
        cleaned, findings = raw_text, []

    return {
        "format": fmt,
        "path": str(target),
        "byte_count": target.stat().st_size,
        "char_count": len(cleaned),
        "stripped_findings": len(findings),
        "content": cleaned,
        "findings": [
            {"label": f.label, "line_number": f.line_number, "evidence": f.evidence}
            for f in findings
        ],
    }
