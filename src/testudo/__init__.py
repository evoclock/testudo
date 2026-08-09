# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Testudo: microVM-first agent runtime.

Purpose: package entry point; exposes version metadata and re-exports the top-level
API surface as it lands during the v0.1 sprint.

Inputs: none (module).

Outputs: ``__version__`` symbol; eventually the public API.

Assumptions: Python 3.11+; governed runs require a host microVM adapter.
Docker remains an explicit compatibility option.
"""

__version__ = "0.1.6"
