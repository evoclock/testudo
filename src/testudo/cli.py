# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

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
import os
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
@click.option("--port", type=int, default=8000, help="Port for the bridge (default 8000).")
@click.option("--host", type=str, default="127.0.0.1", help="Host for the bridge.")
@click.option(
    "--workflows-dir",
    type=click.Path(path_type=Path),
    default=Path("examples"),
    help="Directory of workflow JSON files the bridge will expose.",
)
@click.option(
    "--runs-dir",
    type=click.Path(path_type=Path),
    default=Path("runs"),
    help="Directory for per-run artefacts.",
)
@click.option(
    "--electron-dir",
    type=click.Path(path_type=Path),
    default=Path(__file__).resolve().parent.parent.parent / "electron",
    help="Path to the electron/ directory (auto-detected from the package by default).",
)
@click.option(
    "--no-renderer",
    is_flag=True,
    default=False,
    help="Start only the bridge; do not spawn the renderer.",
)
def ui(
    port: int,
    host: str,
    workflows_dir: Path,
    runs_dir: Path,
    electron_dir: Path,
    no_renderer: bool,
) -> None:
    """Launch the bridge + Electron renderer with a shared bearer token.

    One-command turnkey startup: generates a token, starts ``testudo serve``
    in the background, waits for ``/health`` to respond, then spawns
    ``npm run dev`` in the electron directory with the token exported.
    Ctrl-C tears down both processes cleanly.
    """
    import secrets as _secrets
    import shutil
    import signal
    import subprocess

    if not no_renderer:
        if not electron_dir.is_dir():
            click.echo(
                f"[testudo] electron directory not found at {electron_dir}; "
                "pass --electron-dir or run --no-renderer.",
                err=True,
            )
            sys.exit(2)
        if not (electron_dir / "node_modules").is_dir():
            click.echo(
                f"[testudo] {electron_dir}/node_modules missing; "
                "run `cd electron && npm install` first.",
                err=True,
            )
            sys.exit(2)
        if shutil.which("npm") is None:
            click.echo(
                "[testudo] npm not on PATH; install Node.js or skip with --no-renderer.", err=True
            )
            sys.exit(2)

    token = _secrets.token_urlsafe(32)
    bridge_url = f"http://{host}:{port}"

    bridge_cmd = [
        sys.executable,
        "-m",
        "testudo.cli",
        "serve",
        "--port",
        str(port),
        "--host",
        host,
        "--token",
        token,
        "--workflows-dir",
        str(workflows_dir),
        "--runs-dir",
        str(runs_dir),
    ]

    click.echo(f"[testudo ui] starting bridge on {bridge_url} ...", err=True)
    bridge = subprocess.Popen(bridge_cmd, start_new_session=True)

    renderer: subprocess.Popen[bytes] | None = None
    try:
        _wait_for_health(bridge_url, timeout=20.0)
        click.echo("[testudo ui] bridge is up.", err=True)

        if no_renderer:
            click.echo(
                f"[testudo ui] --no-renderer set; bridge running. "
                f"TESTUDO_BRIDGE_TOKEN={token}\nCtrl-C to stop.",
                err=True,
            )
            bridge.wait()
            return

        env = os.environ.copy()
        env["TESTUDO_BRIDGE_TOKEN"] = token
        env["TESTUDO_BRIDGE_URL"] = bridge_url

        click.echo(f"[testudo ui] launching renderer from {electron_dir} ...", err=True)
        renderer = subprocess.Popen(
            ["npm", "run", "dev"],
            cwd=str(electron_dir),
            env=env,
            start_new_session=True,
        )

        click.echo("[testudo ui] both processes up. Ctrl-C to stop both.", err=True)

        def _shutdown(_sig: int, _frame: object) -> None:
            click.echo("[testudo ui] shutting down ...", err=True)
            for proc, label in ((renderer, "renderer"), (bridge, "bridge")):
                if proc and proc.poll() is None:
                    try:
                        proc.terminate()
                        proc.wait(timeout=5.0)
                    except subprocess.TimeoutExpired:
                        click.echo(f"[testudo ui] {label} did not exit, killing.", err=True)
                        proc.kill()
            sys.exit(0)

        signal.signal(signal.SIGINT, _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)

        renderer.wait()
        bridge.terminate()
        bridge.wait(timeout=5.0)
    except TimeoutError as exc:
        click.echo(f"[testudo ui] {exc}", err=True)
        bridge.terminate()
        if renderer:
            renderer.terminate()
        sys.exit(1)


def _wait_for_health(bridge_url: str, *, timeout: float) -> None:
    """Poll the bridge's /health endpoint until it responds or timeout fires."""
    import time
    import urllib.error
    import urllib.request

    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{bridge_url}/health", timeout=2.0) as resp:
                if 200 <= resp.status < 300:
                    return
        except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
            last_err = exc
        time.sleep(0.3)
    raise TimeoutError(
        f"bridge did not respond on {bridge_url}/health within {timeout:.0f}s "
        f"(last error: {last_err})"
    )


if __name__ == "__main__":
    main()
