"""Testudo: dockerised agent runtime.

Purpose: package entry point; exposes version metadata and re-exports the top-level
API surface as it lands during the v0.1 sprint.

Inputs: none (module).

Outputs: ``__version__`` symbol; eventually the public API.

Assumptions: Python 3.11+; Docker available on the host for runtime invocation.
"""

__version__ = "0.0.1"
