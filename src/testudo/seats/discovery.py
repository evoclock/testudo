# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""D6/D7: candidate merge, caps, and rate limits (bridge-owned memory only).

One scan admits at most 64 merged candidates, at most eight resolved
addresses per candidate, at most eight ports per candidate (the six local
ports plus at most two distinct valid ports observed during the current
bridge process lifetime, newest first), and exactly one eligible address
selected per candidate: the process-lifetime last successful address if
still resolved, otherwise the lexically lowest canonical address. At most
eight probes in flight globally, at most one per candidate. At most one scan
initiation per rolling 10-second interval; no rescan of the same canonical
candidate set within 30 seconds. All scan state resets on bridge restart.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

MAX_CANDIDATES = 64
MAX_ADDRESSES = 8
MAX_PORTS = 8
MAX_OBSERVED_PORTS = 2
MAX_PROBES = 512
MAX_CONCURRENT_GLOBAL = 8
SCAN_INTERVAL_SECONDS = 10.0
RESCAN_INTERVAL_SECONDS = 30.0

SOURCE_PRIORITY = {"tailscale": 0, "mdns": 1, "known-hosts": 2}


@dataclass
class Candidate:
    source: str
    canonical_address: str
    addresses: list[str] = field(default_factory=list)
    observed_ports: list[int] = field(default_factory=list)  # newest first

    def port_set(self, local_ports: tuple[int, ...]) -> list[int]:
        """The six local ports plus at most two observed ports, newest first,
        deduplicated, capped at eight."""
        ports: list[int] = list(local_ports)
        for port in self.observed_ports[:MAX_OBSERVED_PORTS]:
            if port not in ports:
                ports.append(port)
        return ports[:MAX_PORTS]

    def selected_address(self) -> str | None:
        """The lexically lowest canonical address (selection rule for a
        candidate with no process-lifetime last-success record)."""
        if not self.addresses:
            return None
        return sorted(self.addresses)[0]


@dataclass
class ScanLimits:
    """Counted drops, reported without being probed (D6)."""

    dropped_candidates: int = 0
    dropped_addresses: int = 0
    dropped_ports: int = 0
    attempted_probes: int = 0


class ScanRateLimiter:
    """D7 rolling windows; bridge-owned memory only."""

    def __init__(self) -> None:
        self._last_admitted = 0.0
        self._last_sets: dict[frozenset[str], float] = {}

    def admit(self, candidate_keys: frozenset[str], now: float | None = None) -> tuple[bool, float]:
        """Returns (admitted, next_eligible_time). A manual request inside
        either window returns the next eligible time instead of queuing."""
        now = time.monotonic() if now is None else now
        next_by_interval = self._last_admitted + SCAN_INTERVAL_SECONDS
        next_by_set = self._last_sets.get(candidate_keys, 0.0) + RESCAN_INTERVAL_SECONDS
        next_eligible = max(next_by_interval, next_by_set)
        if now < next_eligible:
            return False, next_eligible
        self._last_admitted = now
        self._last_sets[candidate_keys] = now
        # bound memory: keep only recent sets
        if len(self._last_sets) > 256:
            cutoff = now - RESCAN_INTERVAL_SECONDS
            self._last_sets = {
                key: stamp for key, stamp in self._last_sets.items() if stamp >= cutoff
            }
        return True, now


class DiscoveryHistory:
    """Bridge-owned memory-only discovery history (D6). Resets on restart by
    construction: it is never persisted."""

    def __init__(self) -> None:
        self._last_success: dict[str, tuple[str, int, float]] = {}

    def record_success(self, candidate_key: str, address: str, port: int) -> None:
        self._last_success[candidate_key] = (address, port, time.monotonic())

    def last_success(self, candidate_key: str) -> tuple[str, int] | None:
        record = self._last_success.get(candidate_key)
        if record is None:
            return None
        return record[0], record[1]


def merge_candidates(
    raw: list[tuple[str, str, list[str]]],
) -> list[Candidate]:
    """Merge by canonical address and source priority: Tailscale, mDNS, then
    known-hosts. Within a source, the most recently successful candidate
    comes first, followed by lexical canonical address order."""
    by_address: dict[str, Candidate] = {}
    for source, address, resolved in raw:
        existing = by_address.get(address)
        if existing is None:
            existing = Candidate(source, address)
            by_address[address] = existing
        if SOURCE_PRIORITY.get(source, 99) < SOURCE_PRIORITY.get(existing.source, 99):
            existing.source = source
        existing.addresses.extend(resolved)
    candidates = list(by_address.values())
    candidates.sort(
        key=lambda candidate: (
            SOURCE_PRIORITY.get(candidate.source, 99),
            candidate.canonical_address,
        )
    )
    return candidates


def apply_scan_caps(candidates: list[Candidate]) -> tuple[list[Candidate], ScanLimits]:
    """Apply the D6 caps; dropped candidates/addresses/ports are counted and
    reported without being probed."""
    limits = ScanLimits()
    kept = candidates[:MAX_CANDIDATES]
    limits.dropped_candidates = len(candidates) - len(kept)
    result: list[Candidate] = []
    for candidate in kept:
        addresses = candidate.addresses[:MAX_ADDRESSES]
        limits.dropped_addresses += len(candidate.addresses) - len(addresses)
        candidate.addresses = addresses
        result.append(candidate)
    return result, limits
