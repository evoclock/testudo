# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Normative script pins: production constants must equal the spec-extracted
scripts byte-for-byte (the fixture-harness extractor is the oracle)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from testudo.seats import _scripts

SPEC_PATH = Path(__file__).resolve().parents[2] / "docs" / "SEAT_CONTROL_SPEC.md"

pytestmark = pytest.mark.skipif(
    not SPEC_PATH.exists(),
    reason="seat spec (docs/SEAT_CONTROL_SPEC.md) absent in this checkout",
)


def _extract() -> dict[str, str]:
    sys.path.insert(0, str(SPEC_PATH.parents[1] / "tests"))
    from seat_harness.normative import extract_normative_scripts

    return extract_normative_scripts()


def test_normative_scripts_match_spec_byte_for_byte() -> None:
    extracted = _extract()
    assert extracted["GUARD_V1"] == _scripts.GUARD_V1
    assert extracted["LAUNCH_V1"] == _scripts.LAUNCH_V1
    assert extracted["C_PID_V1"] == _scripts.C_PID_V1
    assert extracted["LOG_TAIL_V1"] == _scripts.LOG_TAIL_V1
    assert _scripts.EXEC_V1 == 'set -eu; exec "$@"'


def test_digest_pins_match() -> None:
    assert _scripts.verify_pins() is None
