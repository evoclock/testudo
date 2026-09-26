# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Unit tests for the credential-store backend allowlist (seats.credentials).

Every shape here is synthetic: a fake ``keyring`` module is injected into
``sys.modules``, so no real platform credential store is touched and no
credential values appear anywhere.
"""

from __future__ import annotations

import sys
import types

import pytest

from testudo.seats import credentials


class _FakeBackendBase:
    """In-memory keyring backend; the store dict is per-test."""

    STORE: dict[tuple[str, str], str] = {}

    def set_password(self, service: str, account: str, password: str) -> None:
        self.STORE[(service, account)] = password

    def get_password(self, service: str, account: str) -> str | None:
        return self.STORE.get((service, account))

    def delete_password(self, service: str, account: str) -> None:
        self.STORE.pop((service, account), None)


def _install_keyring(monkeypatch, module_name: str, class_name: str) -> dict:
    """Install a synthetic ``keyring`` module whose selected backend reports
    ``(module_name, class_name)`` as its type identity."""
    store: dict[tuple[str, str], str] = {}
    backend_cls = type(class_name, (_FakeBackendBase,), {"__module__": module_name})
    backend_cls.STORE = store
    instance = backend_cls()
    module = types.ModuleType("keyring")
    # Mirror the real keyring package API: get_keyring plus module-level
    # convenience wrappers over the selected backend.
    module.get_keyring = lambda: instance  # type: ignore[attr-defined]
    module.set_password = instance.set_password  # type: ignore[attr-defined]
    module.get_password = instance.get_password  # type: ignore[attr-defined]
    module.delete_password = instance.delete_password  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "keyring", module)
    return store


def test_approved_backend_is_accepted(monkeypatch) -> None:
    store = _install_keyring(monkeypatch, "keyring.backends.macOS", "Keyring")

    credentials.set_provider_key("databricks", "synthetic-key-material")
    assert credentials.get_provider_key("databricks") == "synthetic-key-material"
    assert (
        store[(credentials.SERVICE_NAME, "testudo.provider-key.v1:databricks")]
        == "synthetic-key-material"
    )
    assert credentials.key_state("databricks").state == "set"

    credentials.delete_provider_key("databricks")
    assert credentials.get_provider_key("databricks") is None
    assert credentials.key_state("databricks").state == "absent"


def test_plaintext_backend_is_rejected(monkeypatch) -> None:
    _install_keyring(monkeypatch, "keyrings.alt.file", "PlaintextKeyring")

    with pytest.raises(credentials.CredentialStoreError) as exc:
        credentials.set_provider_key("databricks", "synthetic-key-material")
    assert exc.value.kind == "credential-store-unapproved"


def test_alt_package_backend_is_rejected(monkeypatch) -> None:
    _install_keyring(monkeypatch, "keyrings.alt", "GnomeKeyring")

    with pytest.raises(credentials.CredentialStoreError) as exc:
        credentials.get_provider_key("databricks")
    assert exc.value.kind == "credential-store-unapproved"


def test_chainer_backend_is_rejected(monkeypatch) -> None:
    # The chainer wraps other backends; its own identity is not approved,
    # which is exactly the case the allowlist must refuse to reason about.
    _install_keyring(monkeypatch, "keyring.backends.chainer", "ChainerBackend")

    with pytest.raises(credentials.CredentialStoreError) as exc:
        credentials.get_provider_key("databricks")
    assert exc.value.kind == "credential-store-unapproved"


def test_get_keyring_failure_is_unavailable(monkeypatch) -> None:
    module = types.ModuleType("keyring")

    def _boom() -> object:
        raise RuntimeError("synthetic backend init failure")

    module.get_keyring = _boom  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "keyring", module)

    with pytest.raises(credentials.CredentialStoreError) as exc:
        credentials.set_provider_key("databricks", "synthetic-key-material")
    assert exc.value.kind == "credential-store-unavailable"


def test_missing_keyring_package_is_unavailable(monkeypatch) -> None:
    # A None entry in sys.modules makes ``import keyring`` raise ImportError.
    monkeypatch.setitem(sys.modules, "keyring", None)

    with pytest.raises(credentials.CredentialStoreError) as exc:
        credentials.get_provider_key("databricks")
    assert exc.value.kind == "credential-store-unavailable"


def test_key_state_reports_unapproved_backend_as_store_error(monkeypatch) -> None:
    _install_keyring(monkeypatch, "keyrings.alt.file", "PlaintextKeyring")

    state = credentials.key_state("databricks")
    assert state.provider_id == "databricks"
    assert state.state == "error: credential-store"
