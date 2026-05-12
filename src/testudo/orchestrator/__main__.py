"""
Script: testudo orchestrator (in-container entry point)

Path: src/testudo/orchestrator/__main__.py

Purpose: in-container entry point invoked by the Docker image's ENTRYPOINT.
v0.1 stub: the full orchestrator implementation lands in Chunk 3. The stub
exists so the runtime layer (Chunk 2) has a real binary to invoke and the
``docker run testudo:0.1`` smoke test produces a deterministic non-zero
exit while we build out the orchestrator.

Inputs: positional argument ``workflow_path`` (default ``/workflow.json``).

Outputs: a notice to stderr; exit code 2 (CLI usage / not implemented).

Assumptions: replaced by the real orchestrator in Chunk 3.

Parameters: none.

Failure Modes: this stub always exits 2.

Author: Julen Gamboa

Created: 2026-05-12

Last Edited: 2026-05-12 by Julen Gamboa
"""

from __future__ import annotations

import sys


def main() -> int:
    workflow_path = sys.argv[1] if len(sys.argv) > 1 else "/workflow.json"
    print(
        "[testudo] orchestrator: v0.1 stub. "
        f"Would execute workflow at {workflow_path}. "
        "Full implementation lands in Chunk 3.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
