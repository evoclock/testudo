# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.runtime.isolation

Purpose: Pydantic model for a workflow's runtime isolation profile, plus the
loader that parses the ``isolation:`` block from ``workflow.json``. The model
is frozen and rejects unknown keys so a typo in the workflow fails loudly.

Inputs: a dict from the workflow's ``isolation:`` block, or ``None``.

Outputs: an ``IsolationProfile`` instance with sensible defaults
(testudo:0.1 image, 1 CPU, 2 GB memory, no network, read-only root with
tmpfs for /tmp, writable rollback layer at /runs).

Assumptions: the governed Runner selects a host microVM by default. The
profile's Docker-compatible image/resource fields are retained for the
explicit Docker compatibility backend; adding another backend is a deliberate
Runner change.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

IsolationPrimitive = Literal["docker"]
NetworkMode = Literal["none", "bridge", "host"]


class IsolationProfile(BaseModel):
    """Runtime isolation profile from a workflow's ``isolation:`` block."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    primitive: IsolationPrimitive = "docker"
    image: str = "testudo:0.1"
    cpu: str = "1.0"
    memory: str = "2g"
    network: NetworkMode = "none"
    rollback: bool = True
    workdir: str = "/runs"
    read_only: bool = True


def load_isolation(block: dict[str, object] | None) -> IsolationProfile:
    """Return an ``IsolationProfile`` from a workflow's ``isolation:`` block."""
    if not block:
        return IsolationProfile()
    return IsolationProfile.model_validate(block)
