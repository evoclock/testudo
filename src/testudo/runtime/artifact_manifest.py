# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-only

"""Closed manifest schema for pinned Linux-backend artifacts.

The Linux-backend work that follows Task 37 must record every download or
generated artifact (Firecracker binary, kernel, rootfs, guest initramfs,
controller bundle) against the exact approved Testudo commit it was verified
for. This module defines that manifest contract now, offline: a closed
pydantic schema and a validator that rejects floating references and
digest-shape violations. It performs no network access and no download; the
Linux-backend work later fills and verifies entries.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ARTIFACT_MANIFEST_SCHEMA = "testudo.artifact.manifest.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class ArtifactManifestEntry(BaseModel):
    """One pinned artifact with its verification provenance.

    ``source_url`` records where the artifact came from; it is evidence, not
    an instruction to fetch. Verification is always local: the recorded
    digest must be recomputed from artifact bytes before any launch.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_: Literal["testudo.artifact.manifest.v1"] = Field(
        "testudo.artifact.manifest.v1", alias="schema"
    )
    name: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    kind: Literal["binary", "kernel", "rootfs", "initramfs", "bundle"]
    source_url: str = Field(min_length=1, max_length=2048)
    sha256: str
    recorded_at: datetime
    testudo_commit: str
    verified: bool = False
    notes: str = Field(default="", max_length=4096)

    @field_validator("sha256")
    @classmethod
    def digest_shape(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("sha256 must be a lowercase 64-hex digest")
        return value

    @field_validator("testudo_commit")
    @classmethod
    def commit_shape(cls, value: str) -> str:
        if _COMMIT.fullmatch(value) is None:
            raise ValueError("testudo_commit must be the exact approved 40-hex commit")
        return value

    @field_validator("source_url")
    @classmethod
    def no_floating_reference(cls, value: str) -> str:
        parsed = urlsplit(value)
        lowered_path = parsed.path.lower().rstrip("/")
        query_values = {item.lower() for _key, item in parse_qsl(parsed.query, keep_blank_values=True)}
        if (
            lowered_path.endswith("/latest")
            or "/latest/" in parsed.path.lower()
            or lowered_path.endswith(":latest")
            or "latest" in query_values
        ):
            raise ValueError("floating 'latest' artifact references are forbidden")
        return value

    @field_validator("recorded_at")
    @classmethod
    def timestamp_is_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("recorded_at must include a timezone")
        return value

    @model_validator(mode="after")
    def verification_is_explicit(self) -> ArtifactManifestEntry:
        if not self.verified and self.notes == "":
            raise ValueError("an unverified manifest entry must record why verification is pending")
        return self


class ArtifactManifest(BaseModel):
    """The closed artifact manifest for one approved Testudo commit."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    schema_: Literal["testudo.artifact.manifest.v1"] = Field(
        "testudo.artifact.manifest.v1", alias="schema"
    )
    testudo_commit: str
    entries: tuple[ArtifactManifestEntry, ...]

    @field_validator("testudo_commit")
    @classmethod
    def commit_shape(cls, value: str) -> str:
        if _COMMIT.fullmatch(value) is None:
            raise ValueError("testudo_commit must be the exact approved 40-hex commit")
        return value

    @model_validator(mode="after")
    def entries_are_unique(self) -> ArtifactManifest:
        names = [entry.name for entry in self.entries]
        if len(names) != len(set(names)):
            raise ValueError("artifact manifest entries must be unique by name")
        for entry in self.entries:
            if entry.testudo_commit != self.testudo_commit:
                raise ValueError("manifest entry is recorded against a different commit")
        return self

    def entry(self, name: str) -> ArtifactManifestEntry:
        """Return the pinned entry for one artifact name or fail closed."""
        for candidate in self.entries:
            if candidate.name == name:
                return candidate
        raise ValueError(f"artifact manifest has no entry for {name!r}")


def validate_manifest_entry(value: dict[str, object]) -> ArtifactManifestEntry:
    """Validate one manifest entry or fail closed."""
    return ArtifactManifestEntry.model_validate(value)


__all__ = [
    "ARTIFACT_MANIFEST_SCHEMA",
    "ArtifactManifest",
    "ArtifactManifestEntry",
    "validate_manifest_entry",
]
