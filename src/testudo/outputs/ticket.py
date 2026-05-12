"""
Module: testudo.outputs.ticket

Purpose: create a ticket (Jira / Linear / GitHub-issue shaped) by POSTing
to a webhook. The webhook URL is supplied per workflow; the payload shape
is the common-denominator (title / body / labels) that downstream services
adapt as needed.

Inputs: a webhook URL; a title; a body; an optional list of labels;
optional timeout.

Outputs: a JSON-serialisable dict (channel, ticket_id when the response
JSON includes one, status code, location URL).

Assumptions: webhook is already in the workflow's
``permissions.network.egress`` allow-list; the orchestrator gated the call.

Failure modes: ``httpx.HTTPError`` subclasses for transport or non-2xx
responses (propagated to the caller).
"""

from __future__ import annotations

from typing import Any

import httpx


def create_ticket(
    webhook_url: str,
    *,
    title: str,
    body: str,
    labels: list[str] | None = None,
    timeout: float = 30.0,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """Create a ticket via a webhook POST."""
    payload: dict[str, Any] = {
        "title": title,
        "body": body,
        "labels": list(labels) if labels else [],
    }

    owned = client is None
    used = client if client is not None else httpx.Client(timeout=timeout)
    try:
        resp = used.post(webhook_url, json=payload)
        resp.raise_for_status()
    finally:
        if owned:
            used.close()

    ticket_id: str | int | None = None
    if resp.headers.get("content-type", "").startswith("application/json"):
        try:
            body_json = resp.json()
            if isinstance(body_json, dict):
                ticket_id = body_json.get("id")
        except ValueError:
            pass

    return {
        "channel": "ticket",
        "ticket_id": ticket_id,
        "url": resp.headers.get("location") or webhook_url,
        "status_code": resp.status_code,
    }
