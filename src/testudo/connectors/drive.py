"""
Module: testudo.connectors.drive

Purpose: Google Drive connector placeholder. v0.1 raises ``NotImplementedError``
with a clear v0.2 plan; the placeholder keeps the connector's public surface
visible (so workflows can declare the dependency in their inputs and receive a
useful error rather than a tool-not-found) without pulling in Google's auth
SDK as a hard dependency for the demo path.

Inputs: a Drive ``file_id`` and optional credentials block.

Outputs: ``NotImplementedError`` in v0.1; a ``StagedInput`` in v0.2 once the
service-account / OAuth-installed-app flow is wired up.

Assumptions: v0.2 will add ``google-auth`` and ``google-api-python-client``
as an optional ``[google]`` extra so the default install stays lean.
"""

from __future__ import annotations

from typing import Any

from testudo.connectors.result import StagedInput


def fetch_drive(
    file_id: str,
    *,
    credentials: dict[str, Any] | None = None,
) -> StagedInput:
    """Fetch a Google Drive file (v0.2)."""
    _ = (file_id, credentials)
    raise NotImplementedError(
        "Google Drive connector lands in v0.2. The v0.1 demo path uses "
        "`connectors.local_file` and `connectors.https_get`; install the "
        "[google] extra in v0.2 to enable Drive ingestion."
    )
