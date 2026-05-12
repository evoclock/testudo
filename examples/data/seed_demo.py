"""
Script: seed_demo.py

Path: examples/data/seed_demo.py

Purpose: build the demo DuckDB used by the meeting-debrief integration test.
Creates ``examples/data/demo.duckdb`` populated with a small ``attendees``
table.

Inputs: none (writes a fixed dataset).

Outputs: ``examples/data/demo.duckdb`` ready for the demo workflow to query.

Assumptions: run from the repo root (``python examples/data/seed_demo.py``)
or invoked from the integration test which patches the path.

Parameters: none.

Failure Modes: I/O errors writing the database; duckdb errors on schema
creation.

Author: Julen Gamboa

Created: 2026-05-12

Last Edited: 2026-05-12 by Julen Gamboa
"""

from __future__ import annotations

from pathlib import Path

import duckdb


def build_demo_database(path: Path) -> Path:
    """Create or refresh the demo attendees database."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    conn = duckdb.connect(str(path))
    try:
        conn.execute(
            """
            CREATE TABLE attendees (
                meeting_id TEXT,
                name TEXT,
                role TEXT
            )
            """
        )
        conn.executemany(
            "INSERT INTO attendees VALUES (?, ?, ?)",
            [
                ("M-001", "Alex", "Engineering Lead"),
                ("M-001", "Bola", "Product Manager"),
                ("M-001", "Charlie", "Designer"),
                ("M-002", "Dani", "CTO"),
                ("M-002", "Erin", "VP Eng"),
            ],
        )
    finally:
        conn.close()
    return path


if __name__ == "__main__":
    target = Path(__file__).parent / "demo.duckdb"
    out = build_demo_database(target)
    print(f"[seed_demo] wrote {out}")
