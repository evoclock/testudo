# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""S3 consent digests.

The bridge canonicalizes and hashes::

    {
      policy_version,
      host_config_excluding_consent,
      ssh_effective,
      trusted_host_key_fingerprint,
      host_lifetime,
      transport,
      ordered_seats
    }

with keys sorted, arrays retained in semantic order, UTF-8, no insignificant
whitespace, and SHA-256 encoded as 64 lowercase hexadecimal characters.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from testudo.seats.config import POLICY_VERSION
from testudo.seats.ssh import EffectiveSsh

CONSENT_TEXT = (
    "Testudo will run the commands shown below on HOST over SSH with your "
    "account's authority. Testudo constructs these commands from strictly "
    "validated fields, but the configured command can execute arbitrary code as "
    "your account. Evaluating SSH configuration can execute Match exec, and "
    "connection options such as ProxyCommand can execute locally, with your local "
    "account's authority; these risks and the resulting effective configuration "
    "are shown in the SSH preview. Configured RemoteCommand, agent forwarding, "
    "and X11 forwarding are disabled by Testudo."
)


def consent_digest(
    *,
    host_config_excluding_consent: dict[str, Any],
    ssh_effective: EffectiveSsh,
    trusted_host_key_fingerprint: str,
    host_lifetime: str,
    transport: dict[str, Any],
    ordered_seats: list[dict[str, Any]],
) -> str:
    """Canonical consent digest (S3). ``host_lifetime`` is the immediately
    refreshed linger observation: ``yes`` | ``no`` | ``unknown``."""
    payload = {
        "policy_version": POLICY_VERSION,
        "host_config_excluding_consent": host_config_excluding_consent,
        "ssh_effective": ssh_effective.canonical_json(),
        "trusted_host_key_fingerprint": trusted_host_key_fingerprint,
        "host_lifetime": host_lifetime,
        "transport": transport,
        "ordered_seats": ordered_seats,
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def consent_text_for(host_label: str) -> str:
    """The required consent disclosure text with HOST substituted."""
    return CONSENT_TEXT.replace("HOST", host_label)
