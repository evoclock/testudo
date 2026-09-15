# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module: testudo.server.auth

Purpose: per-server-session bearer-token authentication. The Electron main
process spawns ``testudo serve`` with a token (or reads the printed token from
stdout) and passes it to the renderer via ``contextBridge`` so the renderer's
``fetch`` calls include ``Authorization: Bearer <token>``. v0.1 is single-user
and single-process; v0.2 will add multi-token + revocation if needed.

Inputs: a token string (constructor); the ``Authorization`` header on each
request (FastAPI dependency).

Outputs: a ``TokenAuth`` dependency used as ``Depends(token_auth)`` on every
protected endpoint.

Failure modes: ``HTTPException(401)`` on missing or wrong token.
"""

from __future__ import annotations

import secrets

from fastapi import Header, HTTPException, status


def generate_token() -> str:
    """Return a new url-safe random bearer token."""
    return secrets.token_urlsafe(32)


class TokenAuth:
    """FastAPI dependency that verifies an ``Authorization: Bearer <token>`` header."""

    def __init__(self, token: str) -> None:
        self._token = token

    def __call__(self, authorization: str = Header(default="")) -> None:
        expected = f"Bearer {self._token}"
        if not secrets.compare_digest(authorization, expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing bearer token",
            )
