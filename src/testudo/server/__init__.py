"""Testudo server package.

Purpose: FastAPI bridge between the Electron UI (or any HTTP client) and the
Python orchestrator. v0.1 endpoints: ``GET /health`` (liveness), ``POST /runs``
(execute a workflow), ``GET /runs/{run_id}`` (fetch a run's results),
``GET /workflows`` (list workflows in a configured directory). Bearer-token
auth is generated at startup and passed to the renderer via the Electron
preload bridge.

Inputs: HTTP requests; configuration via ``create_app(runs_root, ...)``.

Outputs: a configured FastAPI app the caller mounts behind uvicorn.

Side effect: importing ``testudo.server.app`` triggers ``testudo._loaded``
so all built-in tools are registered before the first request lands.
"""

from testudo.server.app import create_app
from testudo.server.auth import generate_token

__all__ = ["create_app", "generate_token"]
