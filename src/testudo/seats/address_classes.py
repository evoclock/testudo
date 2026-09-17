# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""D3 address-class eligibility for discovery and trusted-lan transport."""

from __future__ import annotations

import ipaddress

_LOOPBACK_V4 = ipaddress.ip_network("127.0.0.0/8")
_LOOPBACK_V6 = ipaddress.ip_network("::1/128")
_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def is_loopback(address: str) -> bool:
    parsed = ipaddress.ip_address(address)
    return parsed.is_loopback


def is_discovery_eligible(address: str) -> bool:
    """D3: for discovery and trusted-lan transport only, a connection is
    eligible when its actual peer is loopback, RFC1918, or 100.64.0.0/10.
    Multicast, broadcast, unspecified, link-local, and public-unicast peers
    are ineligible."""
    parsed = ipaddress.ip_address(address)
    if parsed.is_loopback:
        return True
    if parsed.version == 4 and any(parsed in network for network in _RFC1918):
        return True
    return bool(parsed.version == 4 and parsed in _CGNAT)


def is_https_eligible(address: str) -> bool:
    """Verified https transport is exempt from the peer-class rule; its trust
    anchor is certificate and hostname verification."""
    return True
