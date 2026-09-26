# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Path-allowlist tests for the Electron BridgeManager IPC proxy.

The allowlist lives in electron/src/main/bridge.ts as plain regex sources
(``BRIDGE_PATH_ALLOWLIST``). The repo has no JS test runner, so this suite
extracts that array from the TypeScript source and exercises the exact
production patterns — a single source of truth that cannot drift from the
tests: every renderer-legitimate path passes, everything else is rejected
by BridgeManager.request with ``bridge-request-forbidden``.
"""

from __future__ import annotations

import re
from pathlib import Path

BRIDGE_TS = Path(__file__).resolve().parents[1] / "electron" / "src" / "main" / "bridge.ts"

# Every path the renderer actually calls, derived from
# electron/src/renderer/src/lib/api.ts (BridgeClient methods + seatsMethods
# post targets). Keep in sync when a renderer call is added.
RENDERER_CALLS = [
    "/health",
    "/workflows",
    "/tools",
    "/env-check",
    "/workflows/workflow-db-query/readme",
    "/runs",
    "/runs/20260926-abcdef",
    "/seats/config",
    "/seats/draft",
    "/seats/draft/update",
    "/seats/config/apply",
    "/seats/config/delete",
    "/seats/ssh/probe",
    "/seats/ssh/trust",
    "/seats/preview",
    "/seats/consent",
    "/seats/operate",
    "/seats/force-stop-challenge",
    "/seats/provider-key",
    "/seats/provider-key/state",
]


def _allowlist() -> list[re.Pattern[str]]:
    source = BRIDGE_TS.read_text(encoding="utf-8")
    match = re.search(r"BRIDGE_PATH_ALLOWLIST[^=]*=\s*\[(.*?)\];", source, re.DOTALL)
    assert match is not None, "BRIDGE_PATH_ALLOWLIST not found in bridge.ts"
    sources = re.findall(r'"([^"]+)"', match.group(1))
    assert sources, "BRIDGE_PATH_ALLOWLIST extracted no patterns"
    return [re.compile(pattern) for pattern in sources]


def _allowed(patterns: list[re.Pattern[str]], path: str) -> bool:
    return any(pattern.search(path) is not None for pattern in patterns)


def test_allowlist_file_exists() -> None:
    assert BRIDGE_TS.is_file(), f"missing {BRIDGE_TS}"


def test_allowlist_passes_every_renderer_call() -> None:
    patterns = _allowlist()
    for path in RENDERER_CALLS:
        assert _allowed(patterns, path), f"renderer call rejected by allowlist: {path}"


def test_allowlist_rejects_unlisted_paths() -> None:
    patterns = _allowlist()
    rejected = [
        "/",
        "//health",
        "/health/",
        "/admin",
        "/openapi.json",
        "/docs",
        "/redoc",
        "/secrets",
        "/token",
        "/seats",
        "/seats/",
        "/seats/unknown",
        "/seats/provider-key/other",
        "/seats/ssh/probe/extra",
        "/workflows/name/other",
        "/workflows/../seats/config",
        "/runs/a/b",
        "/runs?x=1",
        "/etc/passwd",
        "health",
        "",
    ]
    for path in rejected:
        assert not _allowed(patterns, path), f"path accepted by allowlist: {path!r}"


def test_allowlist_rejects_secret_exfiltration_targets() -> None:
    # Anything that could enumerate or leak credential state must stay
    # unreachable through the renderer IPC proxy.
    patterns = _allowlist()
    for path in [
        "/seats/provider-key/value",
        "/seats/provider-keys",
        "/env",
        "/config",
        "/settings/secrets",
    ]:
        assert not _allowed(patterns, path), f"path accepted by allowlist: {path}"
