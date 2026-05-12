"""
Module: testudo.mcp_servers.file_extractor

Purpose: read-only document extraction MCP server. Parses attachments
(PDF, DOCX, PPTX, HTML, plain text, JSON) and returns cleaned text with
metadata, comments, hidden-unicode, and external-link payloads stripped.
This is the extraction half of the extraction-vs-action separation
mandated by MCP presentation v4 slide 25.

Inputs: ``extract_text`` tool calls with a ``path`` field.

Outputs: a structured result with the cleaned text, a list of stripped
items (metadata fields, comment payloads, links), and the format the
extractor used.

Assumptions: the server has NO write capability. Optional parser
dependencies (``pypdf``, ``python-docx``, ``python-pptx``,
``beautifulsoup4``) are degraded gracefully: if a parser is missing the
extractor returns an ``isError: true`` result naming the missing
dependency rather than executing fallback code.

References:

- MCP presentation v4 slide 25: "One agent parses the document in a
  restricted environment. A second agent, with stronger approvals, acts
  only on the cleaned summary."
- Snyk ToxicSkills (slide 19): attachments and linked content are a
  supply-chain attack surface.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from zipfile import BadZipFile, ZipFile

from testudo.mcp_servers.base import BaseMCPServer, ToolSpec
from testudo.sanitisers.unicode_payload import strip_hidden


def extract_text_file(path: Path) -> str:
    """Read a plain-text file as UTF-8 with replacement on errors."""
    return path.read_text(encoding="utf-8", errors="replace")


def extract_html(path: Path) -> str:
    """Strip tags from an HTML file; comments and scripts are dropped first."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    raw = re.sub(r"<!--.*?-->", "", raw, flags=re.DOTALL)
    raw = re.sub(r"<script\b.*?</script>", "", raw, flags=re.DOTALL | re.IGNORECASE)
    raw = re.sub(r"<style\b.*?</style>", "", raw, flags=re.DOTALL | re.IGNORECASE)
    raw = re.sub(r"<[^>]+>", " ", raw)
    return re.sub(r"\s+", " ", raw).strip()


def extract_json(path: Path) -> str:
    """Pretty-print a JSON file so the model sees structure without metadata."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return json.dumps(data, indent=2, sort_keys=True)


def extract_pptx(path: Path) -> str:
    """Extract text from a PPTX via its internal slide XML (stdlib only).

    PPTX is a ZIP of XML; the slides live under ``ppt/slides/slide*.xml``.
    This avoids the ``python-pptx`` dependency at runtime.
    """
    out: list[str] = []
    try:
        with ZipFile(path) as z:
            names = sorted(n for n in z.namelist() if "slides/slide" in n and n.endswith(".xml"))
            for name in names:
                content = z.read(name).decode("utf-8", errors="replace")
                text = re.sub(r"<a:p>", "\n", content)
                text = re.sub(r"<[^>]+>", " ", text)
                text = re.sub(r"[ \t]+", " ", text)
                text = re.sub(r"\n+", "\n", text).strip()
                out.append(f"=== {name} ===\n{text}")
    except BadZipFile as exc:
        raise ValueError(f"PPTX is not a valid ZIP: {exc}") from exc
    return "\n\n".join(out)


def extract_pdf(path: Path) -> str:
    """Extract text from a PDF using pypdf if available."""
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise RuntimeError(
            "pypdf is required for PDF extraction; install with `uv pip install -e '.[file_ops]'`."
        ) from exc

    reader = PdfReader(str(path))
    return "\n\n".join(page.extract_text() or "" for page in reader.pages)


def extract_docx(path: Path) -> str:
    """Extract text from a DOCX using python-docx if available."""
    try:
        from docx import Document
    except ImportError as exc:
        raise RuntimeError(
            "python-docx is required for DOCX extraction; install with "
            "`uv pip install -e '.[file_ops]'`."
        ) from exc

    doc = Document(str(path))
    return "\n".join(p.text for p in doc.paragraphs)


EXTRACTORS: dict[str, Any] = {
    ".txt": extract_text_file,
    ".md": extract_text_file,
    ".log": extract_text_file,
    ".csv": extract_text_file,
    ".tsv": extract_text_file,
    ".json": extract_json,
    ".html": extract_html,
    ".htm": extract_html,
    ".pptx": extract_pptx,
    ".pdf": extract_pdf,
    ".docx": extract_docx,
}


def _extract_text(arguments: dict[str, Any]) -> dict[str, Any]:
    """``extract_text`` handler: dispatch on suffix, then strip hidden payloads."""
    raw_path = arguments.get("path")
    if not isinstance(raw_path, str):
        return _err("path is required")

    path = Path(raw_path)
    if not path.is_file():
        return _err(f"file not found: {raw_path}")

    extractor = EXTRACTORS.get(path.suffix.lower())
    if extractor is None:
        return _err(f"unsupported file type: {path.suffix}")

    try:
        raw_text = extractor(path)
    except Exception as exc:
        return _err(f"{type(exc).__name__}: {exc}")

    cleaned, findings = strip_hidden(raw_text)
    payload = {
        "format": path.suffix.lower(),
        "byte_count": path.stat().st_size,
        "char_count": len(cleaned),
        "stripped_findings": len(findings),
        "text": cleaned,
        "findings": [
            {"label": f.label, "line_number": f.line_number, "evidence": f.evidence}
            for f in findings
        ],
    }
    return {"isError": False, "content": [{"type": "text", "text": json.dumps(payload)}]}


def _err(text: str) -> dict[str, Any]:
    return {"isError": True, "content": [{"type": "text", "text": text}]}


def build_server() -> BaseMCPServer:
    """Build a configured ``file_extractor`` MCP server."""
    server = BaseMCPServer(name="file_extractor")
    server.register(
        ToolSpec(
            name="extract_text",
            description=(
                "Extract cleaned text from a document at the given path. "
                "READ-ONLY server: no filesystem-write capability. Strips "
                "metadata, HTML comments, hidden-unicode, and base64 payloads "
                "before returning."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "redact_pii": {"type": "boolean"},
                },
                "required": ["path"],
            },
            handler=_extract_text,
        ),
    )
    return server


if __name__ == "__main__":
    build_server().run()
