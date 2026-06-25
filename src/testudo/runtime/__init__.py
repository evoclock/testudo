# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Testudo runtime package.

Purpose: process-isolated execution primitives. v0.1 ships a Docker-backed
runtime; alternative primitives (Firejail, Python-level sandbox) are
planned for v0.2+. Wraps the host-side ``docker run`` invocation so
``runtime/orchestrator/permissions/audit/connectors/...`` can hand it a
workflow plus an isolation profile and get back a ``RunResult``.

Inputs: a workflow path plus an ``IsolationProfile``; optional inputs
directory and timeout.

Outputs: a ``RunResult`` (exit status, stdio, wall-clock runtime); a
per-run audit log file written by the ``Runner``.

Assumptions: v0.1 targets Docker on Linux. The Docker daemon must be
reachable; the host user must have permission to invoke ``docker run``.
"""

from testudo.runtime.docker import RunResult, build_docker_argv, invoke
from testudo.runtime.isolation import (
    IsolationPrimitive,
    IsolationProfile,
    NetworkMode,
    load_isolation,
)
from testudo.runtime.runner import Runner

__all__ = [
    "IsolationPrimitive",
    "IsolationProfile",
    "NetworkMode",
    "RunResult",
    "Runner",
    "build_docker_argv",
    "invoke",
    "load_isolation",
]
