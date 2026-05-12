"""Testudo outputs package.

Purpose: output channel adapters. v0.1 ships a file writer (host-readable artefact
in the rollback layer) and a structured chat-response object the Electron shell
renders inline. v0.2 adds dashboard embed and webhook fan-out.

Inputs: an output object from the workflow's final step (text, structured data,
file payload).

Outputs: persisted artefacts on the host (when the run is committed, not rolled
back) plus an in-memory representation for the UI.

Assumptions: outputs are written to a writable layer that can be discarded if the
workflow rolls back; the audit log records intent-to-write before the file is
flushed so partial failures are reconstructable.
"""
