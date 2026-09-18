# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bridge-owned runtime directories (config and state), created 0700."""

from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> str:
    """The platform user-data directory for seats/state/known-hosts."""
    base = os.environ.get("TESTUDO_DATA_DIR")
    path = Path(base) if base else Path.home() / ".local" / "share" / "testudo"
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return str(path)


def config_dir() -> str:
    base = os.environ.get("TESTUDO_CONFIG_DIR")
    path = Path(base) if base else Path.home() / ".config" / "testudo"
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return str(path)


def state_dir() -> str:
    return data_dir()
