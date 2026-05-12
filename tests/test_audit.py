"""Tests for ``testudo.audit``: ``AuditEvent`` and ``AuditLog``."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from testudo.audit import AuditEvent, AuditLog


def test_audit_event_serialises_with_timestamp() -> None:
    event = AuditEvent(type="workflow_start", run_id="r1", workflow="wf1")
    payload = event.model_dump()
    assert payload["type"] == "workflow_start"
    assert payload["run_id"] == "r1"
    assert isinstance(payload["ts"], datetime)


def test_audit_event_round_trips_via_json() -> None:
    event = AuditEvent(
        type="step_end",
        run_id="r1",
        workflow="wf1",
        step_id="ingest",
        pid=1234,
        runtime_ms=42,
        exit_status=0,
    )
    line = event.model_dump_json()
    parsed = AuditEvent.model_validate_json(line)
    assert parsed == event


def test_audit_event_is_frozen() -> None:
    event = AuditEvent(type="workflow_start", run_id="r1", workflow="wf1")
    with pytest.raises(ValidationError):
        event.run_id = "r2"  # type: ignore[misc]


def test_audit_event_rejects_unknown_type() -> None:
    with pytest.raises(ValidationError):
        AuditEvent(type="not-a-real-type", run_id="r1", workflow="wf1")  # type: ignore[arg-type]


def test_audit_log_creates_parent_directory(tmp_path: Path) -> None:
    log_path = tmp_path / "runs" / "abc" / "audit.jsonl"
    AuditLog(log_path)
    assert log_path.parent.is_dir()


def test_audit_log_appends_one_record_per_emit(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(log_path)
    log.emit(AuditEvent(type="workflow_start", run_id="r1", workflow="wf1"))
    log.emit(AuditEvent(type="workflow_end", run_id="r1", workflow="wf1"))
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    for line in lines:
        assert line.strip()


def test_audit_log_read_returns_events_in_order(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(log_path)
    log.emit(AuditEvent(type="workflow_start", run_id="r1", workflow="wf1"))
    log.emit(AuditEvent(type="step_start", run_id="r1", workflow="wf1", step_id="ingest"))
    events = log.read()
    assert len(events) == 2
    assert events[0].type == "workflow_start"
    assert events[1].step_id == "ingest"


def test_audit_log_read_on_missing_file_returns_empty(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    # AuditLog ensures the parent dir exists but does not create the file itself.
    assert log.read() == []


def test_audit_log_skips_blank_lines(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log = AuditLog(log_path)
    log.emit(AuditEvent(type="workflow_start", run_id="r1", workflow="wf1"))
    # Simulate an accidental blank line in the file.
    with log_path.open("a", encoding="utf-8") as f:
        f.write("\n   \n")
    log.emit(AuditEvent(type="workflow_end", run_id="r1", workflow="wf1"))
    events = log.read()
    assert [e.type for e in events] == ["workflow_start", "workflow_end"]
