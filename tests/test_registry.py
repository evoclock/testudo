# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for ``testudo.orchestrator.registry``: ToolRegistry behaviour."""

from __future__ import annotations

import pytest

from testudo.orchestrator.registry import DEFAULT_REGISTRY, ToolRegistry


def test_register_and_resolve_round_trip() -> None:
    reg = ToolRegistry()

    @reg.register("widgets.shiny")
    def shiny(_ctx: object, **kwargs: object) -> str:
        return f"shiny: {kwargs}"

    assert "widgets.shiny" in reg
    resolved = reg.resolve("widgets.shiny")
    assert resolved is shiny
    assert len(reg) == 1


def test_register_double_raises() -> None:
    reg = ToolRegistry()

    @reg.register("dup")
    def first(_ctx: object) -> int:
        return 1

    with pytest.raises(ValueError, match="already registered"):

        @reg.register("dup")
        def second(_ctx: object) -> int:
            return 2


def test_resolve_missing_raises() -> None:
    reg = ToolRegistry()
    with pytest.raises(KeyError, match="not registered"):
        reg.resolve("ghost")


def test_names_returns_sorted_list() -> None:
    reg = ToolRegistry()

    @reg.register("zeta")
    def _z(_ctx: object) -> int:
        return 0

    @reg.register("alpha")
    def _a(_ctx: object) -> int:
        return 0

    assert reg.names() == ["alpha", "zeta"]


def test_default_registry_has_noop_after_orchestrator_import() -> None:
    # Importing testudo.orchestrator triggers tools.py registration of `noop`.
    import testudo.orchestrator  # noqa: F401

    assert "noop" in DEFAULT_REGISTRY
