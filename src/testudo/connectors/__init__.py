"""Testudo connectors package.

Purpose: input source adapters. v0.1.5 ships local file ingestion, generic
HTTPS retrieval, and document extraction (PDF / DOCX / PPTX / HTML / JSON
/ TXT / MD). For Google Drive content, use ``connectors.https_get`` with
the direct-download URL form (`https://drive.google.com/uc?export=download&id=<FILE_ID>`)
for public link-shared files. Private Drive (service account / OAuth) is
out of scope.

Inputs: a connector specification from a workflow step.

Outputs: a ``StagedInput`` carrying the retrieved content plus provenance
metadata for the audit log.

Side effect: importing this package triggers registration of
``connectors.local_file``, ``connectors.https_get``, and
``connectors.extract_document`` in the orchestrator's ``DEFAULT_REGISTRY``.
"""

from testudo.connectors import tools  # noqa: F401  - registers connector tools
from testudo.connectors.extract import EXTRACTORS, extract_document
from testudo.connectors.https import fetch_https
from testudo.connectors.local import fetch_local
from testudo.connectors.result import StagedInput

__all__ = [
    "EXTRACTORS",
    "StagedInput",
    "extract_document",
    "fetch_https",
    "fetch_local",
]
