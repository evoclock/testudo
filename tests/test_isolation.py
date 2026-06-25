# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for ``testudo.runtime.isolation``: model defaults, frozen, loader."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from testudo.runtime.isolation import IsolationProfile, load_isolation

# ----------------------------------------------------------------------------
# Defaults and immutability
# ----------------------------------------------------------------------------


def test_isolation_defaults_are_secure() -> None:
    profile = IsolationProfile()
    assert profile.primitive == "docker"
    assert profile.image == "testudo:0.1"
    assert profile.cpu == "1.0"
    assert profile.memory == "2g"
    assert profile.network == "none"  # deny-by-default network
    assert profile.read_only is True  # deny-by-default writable root
    assert profile.rollback is True
    assert profile.workdir == "/runs"


def test_isolation_profile_is_frozen() -> None:
    profile = IsolationProfile()
    with pytest.raises(ValidationError):
        profile.image = "evil:latest"  # type: ignore[misc]


def test_isolation_rejects_unknown_keys() -> None:
    with pytest.raises(ValidationError):
        IsolationProfile.model_validate({"image": "x", "kompromat": True})


def test_isolation_rejects_unknown_network_mode() -> None:
    with pytest.raises(ValidationError):
        IsolationProfile.model_validate({"network": "tor"})


def test_isolation_rejects_unknown_primitive() -> None:
    with pytest.raises(ValidationError):
        IsolationProfile.model_validate({"primitive": "qubes"})


# ----------------------------------------------------------------------------
# Loader
# ----------------------------------------------------------------------------


def test_load_isolation_returns_default_for_none() -> None:
    assert load_isolation(None) == IsolationProfile()


def test_load_isolation_returns_default_for_empty_dict() -> None:
    assert load_isolation({}) == IsolationProfile()


def test_load_isolation_from_full_block() -> None:
    block = {
        "primitive": "docker",
        "image": "testudo:0.1",
        "cpu": "0.5",
        "memory": "512m",
        "network": "bridge",
        "rollback": False,
        "workdir": "/work",
        "read_only": False,
    }
    profile = load_isolation(block)
    assert profile.cpu == "0.5"
    assert profile.memory == "512m"
    assert profile.network == "bridge"
    assert profile.rollback is False
    assert profile.read_only is False


def test_load_isolation_from_partial_block_keeps_other_defaults() -> None:
    profile = load_isolation({"memory": "4g"})
    assert profile.memory == "4g"
    assert profile.cpu == "1.0"
    assert profile.network == "none"
    assert profile.read_only is True
