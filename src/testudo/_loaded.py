"""
Module: testudo._loaded

Purpose: convenience side-effect import that registers every built-in tool
package into the orchestrator's ``DEFAULT_REGISTRY``. The CLI and the FastAPI
server both ``import testudo._loaded`` at startup so workflows can reference
``connectors.local_file`` / ``data.duckdb_query`` / ``outputs.file`` /
``sanitisers.pii`` etc. without each surface having to import the right
packages by hand.

Inputs: none.

Outputs: nothing exported; the side-effect of import is registration.

Assumptions: every tool package's ``__init__.py`` imports its ``tools``
submodule which in turn calls ``@register_tool``. Adding new tool packages
later only requires adding one line here.
"""

from __future__ import annotations

# Order does not matter; each package self-registers its own tools.
from testudo import (
    connectors,  # noqa: F401
    data,  # noqa: F401
    orchestrator,  # noqa: F401
    outputs,  # noqa: F401
    sanitisers,  # noqa: F401
)
