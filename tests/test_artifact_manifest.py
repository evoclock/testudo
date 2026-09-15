# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-only

"""Tests for the closed Linux-backend artifact manifest schema.

The manifest is a documentation/contract artifact only: it pins artifacts by
content digest against the exact approved Testudo commit and refuses floating
references. No test here performs any network access or download.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from testudo.runtime.artifact_manifest import ArtifactManifest, validate_manifest_entry


def entry(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "testudo.artifact.manifest.v1",
        "name": "firecracker",
        "kind": "binary",
        "source_url": "https://example.invalid/dist/firecracker/v1.2.3/firecracker",
        "sha256": "a" * 64,
        "recorded_at": datetime.now(UTC).isoformat(),
        "testudo_commit": "b" * 40,
        "verified": True,
    }
    value.update(changes)
    return value


def test_manifest_entry_is_closed_digest_bound_and_commit_bound() -> None:
    parsed = validate_manifest_entry(entry())
    assert parsed.name == "firecracker"
    assert parsed.verified is True
    with pytest.raises(ValidationError, match="64-hex"):
        validate_manifest_entry(entry(sha256="ZZ" * 32))
    with pytest.raises(ValidationError, match="40-hex"):
        validate_manifest_entry(entry(testudo_commit="b" * 39))
    with pytest.raises(ValidationError, match="extra"):
        validate_manifest_entry({**entry(), "surprise": "field"})


def test_manifest_entry_rejects_floating_latest_references() -> None:
    for bad in (
        "https://example.invalid/dist/firecracker/latest",
        "https://example.invalid/latest/firecracker",
        "https://example.invalid/dist/firecracker/latest/",
    ):
        with pytest.raises(ValidationError, match="floating"):
            validate_manifest_entry(entry(source_url=bad))
    # A pinned version URL is accepted.
    validate_manifest_entry(entry(source_url="https://example.invalid/dist/v1.2.3/firecracker"))


def test_unverified_entry_must_record_why() -> None:
    with pytest.raises(ValidationError, match="verification is pending"):
        validate_manifest_entry(entry(verified=False))
    justified = validate_manifest_entry(entry(verified=False, notes="pending local recompute"))
    assert justified.verified is False


def test_manifest_binds_entries_to_one_commit_and_unique_names() -> None:
    manifest = ArtifactManifest.model_validate(
        {
            "schema": "testudo.artifact.manifest.v1",
            "testudo_commit": "b" * 40,
            "entries": [entry(), entry(name="vmlinux", kind="kernel")],
        }
    )
    assert manifest.entry("firecracker").kind == "binary"
    with pytest.raises(ValueError, match="no entry"):
        manifest.entry("missing")
    with pytest.raises(ValidationError, match="unique"):
        ArtifactManifest.model_validate(
            {
                "schema": "testudo.artifact.manifest.v1",
                "testudo_commit": "b" * 40,
                "entries": [entry(), entry()],
            }
        )
    with pytest.raises(ValidationError, match="different commit"):
        ArtifactManifest.model_validate(
            {
                "schema": "testudo.artifact.manifest.v1",
                "testudo_commit": "b" * 40,
                "entries": [entry(testudo_commit="c" * 40)],
            }
        )


def test_manifest_rejects_oci_and_query_latest_and_naive_time() -> None:
    for bad in (
        "docker.io/library/kernel:latest",
        "https://example.invalid/kernel?tag=latest",
    ):
        with pytest.raises(ValidationError, match="floating"):
            validate_manifest_entry(entry(source_url=bad))
    with pytest.raises(ValidationError, match="timezone"):
        validate_manifest_entry(entry(recorded_at="2026-01-01T00:00:00"))
