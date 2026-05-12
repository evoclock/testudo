"""
Module: testudo.connectors.extract

Purpose: pure document-extraction functions shared between the file_extractor
MCP server and the orchestrator's ``connectors.extract_document`` tool. PDF,
DOCX, PPTX, HTML, JSON, and plain-text formats. PPTX uses stdlib zipfile so
no python-pptx runtime dependency is required; PDF and DOCX live behind the
``[file_ops]`` extra (``pypdf``, ``python-docx``).

Inputs: a ``Path`` to the file on disk.

Outputs: the extracted text as a string. All extractors return text in a
form ready for downstream sanitisation; metadata, comments, scripts, and
style blocks are stripped at extraction time.

Failure modes: missing optional dependency raises ``RuntimeError`` with a
clear install hint; malformed PPTX raises ``ValueError``; missing file
raises ``FileNotFoundError`` from the underlying ``read_*``.

Assumptions: the caller has already established read permission on the
path. This module does not consult the permission layer.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from zipfile import BadZipFile, ZipFile


def extract_text_file(path: Path) -> str:
    """Read a plain-text file as UTF-8 with replacement on errors."""
    return path.read_text(encoding="utf-8", errors="replace")


def extract_html(path: Path) -> str:
    """Strip tags from an HTML file; comments, scripts, styles dropped first."""
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
    """Extract text from a PPTX via its internal slide XML (stdlib only)."""
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
    """Extract text from a PDF using pypdf (requires the file_ops extra)."""
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise RuntimeError(
            "pypdf is required for PDF extraction; install with "
            "`uv pip install -e '.[file_ops]'`."
        ) from exc
    reader = PdfReader(str(path))
    return "\n\n".join(page.extract_text() or "" for page in reader.pages)


def extract_docx(path: Path) -> str:
    """Extract text from a DOCX using python-docx (requires the file_ops extra)."""
    try:
        from docx import Document
    except ImportError as exc:
        raise RuntimeError(
            "python-docx is required for DOCX extraction; install with "
            "`uv pip install -e '.[file_ops]'`."
        ) from exc
    doc = Document(str(path))
    return "\n".join(p.text for p in doc.paragraphs)


EXTRACTORS: dict[str, Callable[[Path], str]] = {
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


def extract_document(path: Path) -> tuple[str, str]:
    """Dispatch on suffix; return ``(format, text)``.

    The format is the lower-cased suffix (``".pdf"``, ``".docx"``, etc.).
    Unsupported suffix raises ``ValueError``.
    """
    suffix = path.suffix.lower()
    extractor = EXTRACTORS.get(suffix)
    if extractor is None:
        raise ValueError(f"Unsupported document format: {suffix or '(no suffix)'}")
    return suffix, extractor(path)
