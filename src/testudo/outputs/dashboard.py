"""
Module: testudo.outputs.dashboard

Purpose: emit a dashboard component spec for the Electron renderer to display
inline alongside the chat response. v0.1 produces a generic spec
(``component`` plus ``props``); v0.2 will add a richer schema for Plotly
Dash component embedding.

Inputs: a component identifier (e.g. ``"line_chart"``, ``"data_table"``);
a props dict whose shape is component-specific.

Outputs: a JSON-serialisable dict (channel, component, props).
"""

from __future__ import annotations

from typing import Any


def write_dashboard(component: str, props: dict[str, Any]) -> dict[str, Any]:
    """Build a dashboard component spec for the renderer."""
    return {
        "channel": "dashboard",
        "component": component,
        "props": dict(props),
    }
