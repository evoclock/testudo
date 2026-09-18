# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""D5 credential store: API keys live only in the platform credential store.

macOS uses the Keychain through the ``keyring`` package when available; any
credential-store read/write failure is ``error: credential-store`` with no
plaintext fallback. Keys are never written to JSON, never logged, and never
returned to the renderer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SERVICE_NAME = "testudo"
KEY_SCHEMA = "testudo.provider-key.v1"


class CredentialStoreError(Exception):
    """``error: credential-store`` — no plaintext fallback."""


@dataclass(frozen=True)
class KeyState:
    provider_id: str
    state: str  # "set" | "absent" | "error: credential-store"


def _keyring() -> Any:
    try:
        import keyring  # type: ignore[import-not-found]

        return keyring
    except ImportError:
        return None


def set_provider_key(provider_id: str, key: str) -> None:
    """Store the key in the platform credential store. ``key`` is accepted
    only on write and never retained in renderer-readable state."""
    backend: Any = _keyring()
    if backend is None:
        raise CredentialStoreError("no platform credential store available")
    try:
        backend.set_password(SERVICE_NAME, _account(provider_id), key)
    except Exception as exc:  # keyring raises broad errors
        raise CredentialStoreError(str(exc)) from exc


def get_provider_key(provider_id: str) -> str | None:
    """Read the key for attaching to provider requests (bridge-side only)."""
    backend: Any = _keyring()
    if backend is None:
        raise CredentialStoreError("no platform credential store available")
    try:
        value: str | None = backend.get_password(SERVICE_NAME, _account(provider_id))
        return value
    except Exception as exc:
        raise CredentialStoreError(str(exc)) from exc


def delete_provider_key(provider_id: str) -> None:
    backend: Any = _keyring()
    if backend is None:
        raise CredentialStoreError("no platform credential store available")
    try:
        backend.delete_password(SERVICE_NAME, _account(provider_id))
    except Exception as exc:
        raise CredentialStoreError(str(exc)) from exc


def key_state(provider_id: str) -> KeyState:
    """The renderer-visible state: never the key bytes."""
    try:
        present = get_provider_key(provider_id) is not None
    except CredentialStoreError:
        return KeyState(provider_id, "error: credential-store")
    return KeyState(provider_id, "set" if present else "absent")


def _account(provider_id: str) -> str:
    return f"{KEY_SCHEMA}:{provider_id}"
