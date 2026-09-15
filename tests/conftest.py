# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Shared pytest fixtures and configuration for Testudo tests.

Purpose: provide reusable temporary run-directory, sample workflow specifications,
and Docker availability marker so tests can skip cleanly when Docker is missing.

Inputs: pytest configuration.

Outputs: fixtures consumed by tests.

Assumptions: pytest >= 8; pytest-asyncio available for async fixtures.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    """Per-test run directory inside pytest's tmp_path."""
    target = tmp_path / "run"
    target.mkdir()
    return target


@pytest.fixture(scope="session")
def docker_available() -> bool:
    """True if Docker is available on PATH and the daemon responds."""
    return shutil.which("docker") is not None


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Auto-skip tests marked ``docker`` when Docker is unavailable."""
    del config  # required by pytest's hook signature; not used here
    if shutil.which("docker") is not None:
        return
    skip_docker = pytest.mark.skip(reason="docker unavailable on this host")
    for item in items:
        if "docker" in item.keywords:
            item.add_marker(skip_docker)
