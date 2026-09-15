# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-only

"""Canonical Testudo-owned guest containment taxonomy identity."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from importlib.resources import files
from types import MappingProxyType
from typing import Any

TAXONOMY_SCHEMA = "guest-containment-taxonomy.v1"
LOG_SCHEMA = "agentic-driver.guest-containment.log.v1"
KILLSWITCH_SCHEMA = "agentic-driver.guest-containment.killswitch.v1"


def taxonomy_bytes() -> bytes:
    """Return the packaged canonical taxonomy bytes."""
    return files("testudo.runtime").joinpath("guest_containment_taxonomy.v1.json").read_bytes()


def taxonomy_sha256() -> str:
    """Return the canonical digest bound into contracts and receipts."""
    return hashlib.sha256(taxonomy_bytes()).hexdigest()


def taxonomy() -> Mapping[str, Any]:
    """Load and validate the closed taxonomy artifact."""
    value = json.loads(taxonomy_bytes())
    if not isinstance(value, dict) or set(value) != {"schema", "description", "rules", "residual"}:
        raise RuntimeError("guest containment taxonomy has an invalid shape")
    if value.get("schema") != TAXONOMY_SCHEMA or not isinstance(value.get("rules"), list):
        raise RuntimeError("guest containment taxonomy has an invalid schema")
    return MappingProxyType(value)


def containment_contract() -> dict[str, object]:
    """Return the immutable monitor identity for a guest bootstrap contract."""
    taxonomy()
    return {
        "schema": LOG_SCHEMA,
        "taxonomy": TAXONOMY_SCHEMA,
        "taxonomy_sha256": taxonomy_sha256(),
        "killswitch_schema": KILLSWITCH_SCHEMA,
        "deny_by_default": True,
    }


__all__ = [
    "KILLSWITCH_SCHEMA",
    "LOG_SCHEMA",
    "TAXONOMY_SCHEMA",
    "containment_contract",
    "taxonomy",
    "taxonomy_bytes",
    "taxonomy_sha256",
]
