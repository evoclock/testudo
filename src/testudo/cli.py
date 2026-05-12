"""
Script: testudo CLI entry point

Path: src/testudo/cli.py

Purpose: command-line entry point for Testudo. Subcommands: ``run`` (execute a
workflow inside a Testudo container), ``ui`` (launch the Electron shell against a
local Testudo instance), ``inspect`` (read an audit log), ``version``.

Inputs: command-line arguments parsed by Click; configuration from environment
variables (``TESTUDO_RUN_DIR``, ``TESTUDO_DOCKER_IMAGE``).

Outputs: process exit status; result files in the run directory; audit log in the
run directory; UI process (when ``ui`` subcommand is used).

Assumptions: Docker daemon reachable; Python 3.11+; Electron available on PATH for
the ``ui`` subcommand.

Parameters: see ``--help`` per subcommand. Defaults are wired for the demo path.

Failure Modes: Docker unavailable (returns non-zero exit, message to stderr);
malformed workflow.json (returns non-zero, schema-validation error to stderr);
permission denied during run (returns non-zero, audit record retained).

Author: Julen Gamboa

Created: 2026-05-12

Last Edited: 2026-05-12 by Julen Gamboa
"""

from __future__ import annotations

import sys

import click

from testudo import __version__


@click.group()
@click.version_option(__version__, prog_name="testudo")
def main() -> None:
    """Testudo: dockerised agent runtime."""


@main.command()
@click.argument("workflow", type=click.Path(exists=True, dir_okay=False))
@click.option("--input", "inputs", multiple=True, help="Input file(s) for the workflow.")
@click.option("--run-dir", type=click.Path(), default=None, help="Directory for run artefacts.")
def run(workflow: str, inputs: tuple[str, ...], run_dir: str | None) -> None:
    """Run a workflow inside a Testudo container."""
    click.echo("[testudo] run is not yet implemented (v0.1 in progress).", err=True)
    click.echo(f"  workflow: {workflow}")
    click.echo(f"  inputs:   {list(inputs)}")
    click.echo(f"  run_dir:  {run_dir}")
    sys.exit(2)


@main.command()
def ui() -> None:
    """Launch the Electron shell against a local Testudo instance."""
    click.echo("[testudo] ui is not yet implemented (v0.1 in progress).", err=True)
    sys.exit(2)


@main.command()
@click.argument("audit_log", type=click.Path(exists=True, dir_okay=False))
def inspect(audit_log: str) -> None:
    """Read and pretty-print a Testudo audit log."""
    click.echo("[testudo] inspect is not yet implemented (v0.1 in progress).", err=True)
    click.echo(f"  audit_log: {audit_log}")
    sys.exit(2)


if __name__ == "__main__":
    main()
