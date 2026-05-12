"""Testudo connectors package.

Purpose: input-source adapters. v0.1 ships local file upload and generic HTTPS
retrieval. v0.2 will add Google Drive, Dropbox, Slack, and Confluence.

Inputs: a connector specification from the workflow (URI plus auth).

Outputs: a ``StagedInput`` object that points to the file inside the container's
read-mounted ``inputs/`` directory and carries provenance metadata for the audit
log.

Assumptions: all retrieved content passes through ``sanitisers/`` before any
downstream step consumes it; connectors do not bypass the permission model for
network egress.
"""
