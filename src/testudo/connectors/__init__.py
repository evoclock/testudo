"""Testudo connectors package.

Purpose: input source adapters. v0.1 ships local file ingestion and generic
HTTPS retrieval; the Google Drive connector is scaffolded for v0.2.

Inputs: a connector specification from a workflow step.

Outputs: a ``StagedInput`` carrying the retrieved content plus provenance
metadata for the audit log.

Side effect: importing this package triggers registration of
``connectors.local_file``, ``connectors.https_get``, and
``connectors.google_drive`` (placeholder) in the orchestrator's
``DEFAULT_REGISTRY``.
"""

from testudo.connectors import tools  # noqa: F401  - registers connector tools
from testudo.connectors.drive import fetch_drive
from testudo.connectors.extract import EXTRACTORS, extract_document
from testudo.connectors.https import fetch_https
from testudo.connectors.local import fetch_local
from testudo.connectors.result import StagedInput

__all__ = [
    "EXTRACTORS",
    "StagedInput",
    "extract_document",
    "fetch_drive",
    "fetch_https",
    "fetch_local",
]
