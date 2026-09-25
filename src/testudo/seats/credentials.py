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

ERROR_UNAVAILABLE = "credential-store-unavailable"
ERROR_UNAPPROVED = "credential-store-unapproved"
ERROR_OPERATION = "credential-store-operation-failed"

_APPROVED_BACKENDS = frozenset(
    {
        ("keyring.backends.macOS", "Keyring"),
        ("keyring.backends.Windows", "WinVaultKeyring"),
        ("keyring.backends.SecretService", "Keyring"),
        ("keyring.backends.kwallet", "DBusKeyring"),
    }
)


class CredentialStoreError(Exception):
    """Stable, value-free credential-store failure."""

    def __init__(self, kind: str) -> None:
        self.kind = kind
        super().__init__(kind)


@dataclass(frozen=True)
class KeyState:
    provider_id: str
    state: str  # "set" | "absent" | "error: credential-store"


def _keyring() -> Any:
    try:
        import keyring  # type: ignore[import-not-found]
    except ImportError as exc:
        raise CredentialStoreError(ERROR_UNAVAILABLE) from exc

    try:
        selected = keyring.get_keyring()
    except Exception as exc:
        raise CredentialStoreError(ERROR_UNAVAILABLE) from exc
    identity = (type(selected).__module__, type(selected).__name__)
    if identity not in _APPROVED_BACKENDS:
        raise CredentialStoreError(ERROR_UNAPPROVED)
    return keyring


def set_provider_key(provider_id: str, key: str) -> None:
    """Store the key in the platform credential store. ``key`` is accepted
    only on write and never retained in renderer-readable state."""
    backend: Any = _keyring()
    try:
        backend.set_password(SERVICE_NAME, _account(provider_id), key)
    except Exception as exc:  # keyring backends expose heterogeneous exceptions
        raise CredentialStoreError(ERROR_OPERATION) from exc


def get_provider_key(provider_id: str) -> str | None:
    """Read the key for attaching to provider requests (bridge-side only)."""
    backend: Any = _keyring()
    try:
        value: str | None = backend.get_password(SERVICE_NAME, _account(provider_id))
        return value
    except Exception as exc:
        raise CredentialStoreError(ERROR_OPERATION) from exc


def delete_provider_key(provider_id: str) -> None:
    backend: Any = _keyring()
    try:
        backend.delete_password(SERVICE_NAME, _account(provider_id))
    except Exception as exc:
        raise CredentialStoreError(ERROR_OPERATION) from exc


def key_state(provider_id: str) -> KeyState:
    """The renderer-visible state: never the key bytes."""
    try:
        present = get_provider_key(provider_id) is not None
    except CredentialStoreError:
        return KeyState(provider_id, "error: credential-store")
    return KeyState(provider_id, "set" if present else "absent")


def _account(provider_id: str) -> str:
    return f"{KEY_SCHEMA}:{provider_id}"
