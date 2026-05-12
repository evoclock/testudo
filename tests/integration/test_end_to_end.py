"""End-to-end test: run the meeting-debrief workflow through the orchestrator.

This is the v0.1 vertical slice exercised: connector (local file) → sanitiser
(PII + injection) → data adapter (DuckDB) → output channels (file + chat).
The workflow runs on the host (no Docker) so it works in any environment;
the equivalent Docker-isolated run is gated on the @pytest.mark.docker marker
in test_docker.py and lands in v0.1.5.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from testudo import _loaded  # noqa: F401  - registers all built-in tools
from testudo.audit import AuditLog
from testudo.orchestrator import Executor, load_workflow, resolve_permissions

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = REPO_ROOT / "examples"


@pytest.fixture
def demo_database(tmp_path: Path) -> Path:
    sys.path.insert(0, str(EXAMPLES / "data"))
    try:
        from seed_demo import build_demo_database
    finally:
        sys.path.pop(0)
    return build_demo_database(tmp_path / "demo.duckdb")


@pytest.fixture
def transcript_file(tmp_path: Path) -> Path:
    src = EXAMPLES / "data" / "transcript.md"
    target = tmp_path / "transcript.md"
    target.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return target


def test_meeting_debrief_runs_end_to_end(
    tmp_path: Path,
    demo_database: Path,
    transcript_file: Path,
) -> None:
    workflow_path = EXAMPLES / "workflow-meeting-debrief.json"
    workflow = load_workflow(workflow_path)

    inputs = {
        "transcript_path": str(transcript_file),
        "demo_db_path": str(demo_database),
        "meeting_id": "M-001",
        "output_path": str(tmp_path / "debrief.md"),
    }

    audit = AuditLog(tmp_path / "audit.jsonl")
    executor = Executor(audit=audit)
    permissions = resolve_permissions(workflow)
    results = executor.run(workflow, inputs, permissions, run_id="integration")

    # All five steps executed without error
    assert set(results) == {
        "ingest",
        "sanitise",
        "lookup_attendees",
        "write_debrief",
        "respond",
    }
    for step_id, result in results.items():
        assert result.error is None, f"{step_id} failed: {result.error}"
        assert not result.skipped, f"{step_id} unexpectedly skipped"

    # Sanitiser ran in redact mode and produced cleaned content
    sanitise_out = results["sanitise"].output
    assert sanitise_out["decision"] in {"accept", "redact"}
    assert "content" in sanitise_out

    # DuckDB returned attendees for M-001
    rows = results["lookup_attendees"].output["rows"]
    assert len(rows) == 3
    names = {r["name"] for r in rows}
    assert names == {"Alex", "Bola", "Charlie"}

    # Debrief file landed at the configured output_path
    debrief_path = Path(results["write_debrief"].output["destination"])
    assert debrief_path.exists()
    assert debrief_path.read_text(encoding="utf-8")

    # Chat response references the debrief file
    chat = results["respond"].output
    assert chat["channel"] == "chat"
    assert any(a.endswith("debrief.md") for a in chat["attachments"]), chat["attachments"]

    # Audit log captured workflow + step events
    events = audit.read()
    types = [e.type for e in events]
    assert types.count("step_start") == 5
    assert types.count("step_end") == 5


def test_workflow_json_validates(tmp_path: Path) -> None:
    workflow_path = EXAMPLES / "workflow-meeting-debrief.json"
    raw = json.loads(workflow_path.read_text(encoding="utf-8"))
    # must round-trip through Workflow.model_validate without error
    load_workflow(workflow_path)
    assert raw["name"] == "meeting-debrief-v01"
    assert len(raw["steps"]) == 5
