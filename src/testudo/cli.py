"""
Script: testudo CLI entry point

Path: src/testudo/cli.py

Purpose: command-line entry point. Subcommands: ``run`` (execute a workflow
on the host directly), ``serve`` (launch the FastAPI bridge for the
Electron UI), ``inspect`` (read an audit log), ``ui`` (launch the Electron
shell against a local serve), ``demo init`` (create the demo DuckDB).

Inputs: command-line arguments parsed by Click; environment variables
(``TESTUDO_RUNS_DIR``, ``TESTUDO_WORKFLOWS_DIR``, ``TESTUDO_TOKEN``).

Outputs: process exit status; per-step status to stderr for ``run``;
HTTP server log for ``serve``; pretty-printed audit log for ``inspect``.

Assumptions: ``testudo._loaded`` is imported by ``run`` and the server so
all built-in tool packages are registered. ``serve`` requires the
``[serve]`` extra (``uv pip install -e ".[serve]"``).

Author: Julen Gamboa

Created: 2026-05-12

Last Edited: 2026-05-12 by Julen Gamboa
"""

from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

import click

from testudo import __version__


@click.group()
@click.version_option(__version__, prog_name="testudo")
def main() -> None:
    """Testudo: dockerised agent runtime."""


@main.command()
@click.argument("workflow_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--inputs-json",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a JSON file of workflow inputs.",
)
@click.option(
    "--runs-dir",
    type=click.Path(path_type=Path),
    default=Path("runs"),
    help="Directory for per-run artefacts (default ./runs).",
)
@click.option(
    "--run-id",
    type=str,
    default=None,
    help="Explicit run identifier (default: random hex).",
)
def run(
    workflow_path: Path,
    inputs_json: Path | None,
    runs_dir: Path,
    run_id: str | None,
) -> None:
    """Run a workflow on the host directly (no Docker isolation)."""
    from testudo import _loaded  # noqa: F401  - registers all built-in tools
    from testudo.audit import AuditLog
    from testudo.orchestrator import Executor, load_workflow, resolve_permissions

    try:
        workflow = load_workflow(workflow_path)
    except Exception as exc:
        click.echo(f"[testudo] failed to load workflow: {exc}", err=True)
        sys.exit(2)

    inputs: dict[str, object] = {}
    if inputs_json is not None:
        try:
            inputs = json.loads(inputs_json.read_text(encoding="utf-8"))
        except Exception as exc:
            click.echo(f"[testudo] failed to load inputs: {exc}", err=True)
            sys.exit(2)

    rid = run_id or secrets.token_hex(6)
    run_directory = runs_dir / rid
    run_directory.mkdir(parents=True, exist_ok=True)
    audit = AuditLog(run_directory / "audit.jsonl")

    executor = Executor(audit=audit)
    permissions = resolve_permissions(workflow)
    results = executor.run(workflow, inputs, permissions, run_id=rid)

    failed = 0
    for sid, result in results.items():
        if result.error is not None:
            click.echo(f"[FAIL] {sid}: {result.error}", err=True)
            failed += 1
        elif result.skipped:
            click.echo(f"[SKIP] {sid}", err=True)
        else:
            click.echo(f"[OK]   {sid}", err=True)

    click.echo(f"\nrun_id: {rid}")
    click.echo(f"audit:  {run_directory / 'audit.jsonl'}")
    sys.exit(0 if failed == 0 else 1)


@main.command()
@click.option("--port", type=int, default=8000, help="Port to bind (default 8000).")
@click.option("--host", type=str, default="127.0.0.1", help="Host to bind (default localhost).")
@click.option(
    "--runs-dir",
    type=click.Path(path_type=Path),
    default=Path("runs"),
    help="Directory for per-run artefacts.",
)
@click.option(
    "--workflows-dir",
    type=click.Path(path_type=Path),
    default=Path("workflows"),
    help="Directory of workflow JSON files for /workflows listing.",
)
@click.option(
    "--token",
    type=str,
    default=None,
    help="Bearer token (default: random; printed to stderr).",
)
def serve(
    port: int,
    host: str,
    runs_dir: Path,
    workflows_dir: Path,
    token: str | None,
) -> None:
    """Launch the FastAPI bridge for the Electron UI."""
    try:
        import uvicorn

        from testudo.server import create_app, generate_token
    except ImportError as exc:
        click.echo(
            f'[testudo] serve requires the [serve] extra: {exc}\nRun: uv pip install -e ".[serve]"',
            err=True,
        )
        sys.exit(2)

    chosen_token = token or generate_token()
    click.echo(f"[testudo] bearer token: {chosen_token}", err=True)

    app = create_app(
        runs_root=runs_dir,
        workflows_root=workflows_dir,
        token=chosen_token,
    )
    uvicorn.run(app, host=host, port=port, log_level="info")


@main.command()
@click.argument("audit_log", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def inspect(audit_log: Path) -> None:
    """Pretty-print a Testudo audit log."""
    from testudo.audit import AuditLog

    log = AuditLog(audit_log)
    events = log.read()
    if not events:
        click.echo("(no events)")
        return

    for ev in events:
        line = f"{ev.ts.isoformat()} [{ev.type}] run={ev.run_id}"
        if ev.step_id:
            line += f" step={ev.step_id}"
        if ev.error:
            line += f" error={ev.error}"
        elif ev.exit_status is not None:
            line += f" exit={ev.exit_status}"
        click.echo(line)


@main.command()
def ui() -> None:
    """Launch the Electron shell (assumes `npm install` already ran in electron/)."""
    click.echo(
        "[testudo] ui scaffolded but not yet wired to the FastAPI bridge.\n"
        "Run `cd electron && npm install && npm start` for the v0.1 UI shell.\n"
        "Full TS/React migration lands in v0.1.5.",
        err=True,
    )
    sys.exit(2)


if __name__ == "__main__":
    main()
