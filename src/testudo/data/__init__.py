"""Testudo data package.

Purpose: database and warehouse adapters. v0.1 default is DuckDB for a local,
zero-config demo path; the Databricks adapter is scaffolded for swap-in via PAT
auth. Service-principal auth comes in v0.2.

Inputs: a connection specification from the workflow plus a parameterised query
or DataFrame operation.

Outputs: query results as either pandas DataFrames or PyArrow tables, with the
query, parameters, and execution metadata routed to the audit log.

Assumptions: queries are parameterised at the adapter boundary (no string
interpolation in the workflow code); query allow-listing is the responsibility of
the workflow's ``permissions:`` block.
"""
