"""Testudo runtime package.

Purpose: process-isolated execution primitives. Wraps Docker (and, later, alternative
primitives) so that a workflow runs inside a container with namespaces, cgroup limits,
and deny-by-default networking.

Inputs: a workflow specification (`testudo.orchestrator.Workflow`) plus an isolation
profile (resource limits, network allow-list, mounted paths).

Outputs: a ``Run`` handle that exposes the audit record, exit status, and any output
artefacts produced by the workflow.

Assumptions: v0.1 targets Docker on Linux. The Docker daemon must be reachable; the
host user must have permission to invoke ``docker run``.
"""
