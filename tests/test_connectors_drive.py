"""Tests for ``testudo.connectors.drive``: v0.1 placeholder behaviour."""

from __future__ import annotations

import pytest

from testudo.connectors.drive import fetch_drive


def test_fetch_drive_raises_not_implemented_in_v01() -> None:
    with pytest.raises(NotImplementedError, match=r"v0\.2"):
        fetch_drive("file-id-123")
