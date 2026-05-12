"""Load + run tests for every workflow JSON in examples/.

Each example workflow is exercised against deterministic inputs:
- pdf-debrief: against examples/data/sample.md (markdown is a supported document format).
- url-fetch: against an httpx.MockTransport so no real HTTP is fetched.
- db-query: against an in-memory DuckDB.
- pdf-summarise: against a mocked Ollama transport.
- meeting-debrief: covered separately in tests/integration/test_end_to_end.py.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from testudo import _loaded  # noqa: F401  - register all built-in tools
from testudo.audit import AuditLog
from testudo.orchestrator import Executor, load_workflow, resolve_permissions

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = REPO_ROOT / "examples"


def _all_example_workflows() -> list[Path]:
    return sorted(EXAMPLES.glob("workflow-*.json"))


@pytest.mark.parametrize("workflow_path", _all_example_workflows(), ids=lambda p: p.name)
def test_workflow_loads(workflow_path: Path) -> None:
    """Every example workflow loads and validates against the schema."""
    wf = load_workflow(workflow_path)
    assert wf.name
    assert wf.steps
    for step in wf.steps:
        assert step.id
        assert step.uses


def _run(workflow_name: str, inputs: dict, tmp_path: Path) -> dict:
    wf = load_workflow(EXAMPLES / workflow_name)
    audit = AuditLog(tmp_path / "audit.jsonl")
    executor = Executor(audit=audit)
    perms = resolve_permissions(wf)
    return executor.run(wf, inputs, perms, run_id="test")


def test_pdf_debrief_runs_against_sample_markdown(tmp_path: Path) -> None:
    output = tmp_path / "debrief.md"
    results = _run(
        "workflow-pdf-debrief.json",
        {"pdf_path": str(EXAMPLES / "data" / "sample.md"), "output_path": str(output)},
        tmp_path,
    )
    assert set(results) == {"extract", "sanitise", "write_debrief", "respond"}
    for step_id, result in results.items():
        assert result.error is None, f"{step_id} failed: {result.error}"
    assert output.exists()
    # Sample.md contains canonical PII; sanitiser should have flagged at least one finding
    sanitise = results["sanitise"].output
    assert sanitise["decision"] in {"redact", "reject"}
    assert sanitise["high_count"] + sanitise["critical_count"] >= 1


def test_url_fetch_runs_against_mock_transport(tmp_path: Path) -> None:
    """Inject an httpx.MockTransport via fetch_https' client= parameter."""
    from testudo.connectors import https as https_module

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/plain"},
            text="Fetched URL body. Email me@example.com if you have questions.",
        )

    real_fetch = https_module.fetch_https

    def patched_fetch(url, *, max_bytes=10485760, timeout=30.0, client=None):
        with httpx.Client(transport=httpx.MockTransport(handler)) as c:
            return real_fetch(url, max_bytes=max_bytes, timeout=timeout, client=c)

    output = tmp_path / "url.md"
    with patch.object(https_module, "fetch_https", side_effect=patched_fetch):
        # The tool reads from the patched module at call time
        from testudo.connectors import tools as connector_tools

        with patch.object(connector_tools, "fetch_https", side_effect=patched_fetch):
            results = _run(
                "workflow-url-fetch.json",
                {
                    "url": "https://example.com/article",
                    "output_path": str(output),
                    "max_bytes": 10485760,
                },
                tmp_path,
            )

    assert set(results) == {"fetch", "sanitise", "write_summary", "respond"}
    for step_id, result in results.items():
        assert result.error is None, f"{step_id} failed: {result.error}"
    assert output.exists()


def test_db_query_runs_against_in_memory_duckdb(tmp_path: Path) -> None:
    # Seed an in-memory DuckDB and store its path
    sys.path.insert(0, str(EXAMPLES / "data"))
    try:
        from seed_demo import build_demo_database
    finally:
        sys.path.pop(0)

    db_path = build_demo_database(tmp_path / "demo.duckdb")
    output = tmp_path / "rows.md"
    results = _run(
        "workflow-db-query.json",
        {
            "database_path": str(db_path),
            "query": "SELECT name, role FROM attendees WHERE meeting_id = 'M-001'",
            "parameters": [],
            "output_path": str(output),
        },
        tmp_path,
    )
    assert set(results) == {"query", "write_results", "respond"}
    for step_id, result in results.items():
        assert result.error is None, f"{step_id} failed: {result.error}"
    rows = results["query"].output["rows"]
    assert len(rows) == 3
    assert {r["name"] for r in rows} == {"Alex", "Bola", "Charlie"}


def test_pdf_summarise_runs_against_mock_ollama(tmp_path: Path) -> None:
    """Patch the ollama client to avoid hitting a real daemon."""
    from testudo.models import ollama as ollama_module

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"message": {"content": "- Point one\n- Point two\n- Point three"}}
        )

    real_ollama_chat = ollama_module.ollama_chat

    def patched_ollama_chat(**kwargs):
        kwargs.pop("client", None)
        with httpx.Client(transport=httpx.MockTransport(handler)) as c:
            return real_ollama_chat(**kwargs, client=c)

    output = tmp_path / "summary.md"
    from testudo.models import tools as model_tools

    with patch.object(model_tools, "ollama_chat", side_effect=patched_ollama_chat):
        results = _run(
            "workflow-pdf-summarise.json",
            {
                "pdf_path": str(EXAMPLES / "data" / "sample.md"),
                "model": "minimax-m2.5",
                "system_prompt": "be brief",
                "output_path": str(output),
            },
            tmp_path,
        )

    assert set(results) == {"extract", "summarise", "write_summary", "respond"}
    for step_id, result in results.items():
        assert result.error is None, f"{step_id} failed: {result.error}"
    assert output.exists()
    summary_text = output.read_text(encoding="utf-8")
    assert "Point one" in summary_text
