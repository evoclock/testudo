# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Seat-control production implementation (docs/SEAT_CONTROL_SPEC.md Rev 5).

Submodules:

- ``validation``  — C1 field-validation classes.
- ``render``      — C2 remote-command construction algorithm.
- ``_scripts``    — byte-exact normative shell constants with digest pins.
- ``config``      — P1/P2/P3 closed-schema persistence (seats.v1.json).
- ``state``       — P4 runtime state persistence (state.v1.json).
- ``discovery``   — D1-D8 Mode 1 discovery.
- ``credentials`` — D5 platform credential store.
- ``ssh``         — S1/S2 SSH descriptors, effective-config resolution, trust.
- ``consent``     — S3 consent digests.
- ``guard``       — L1/L2 local lock + GUARD_V1 controller protocol.
- ``transport``   — T1/T2 endpoint transports and polling.
- ``controller``  — seat controllers (templates A/B/C), L3/U1 gates.
- ``sanitize``    — R2 output boundary.
- ``store``       — in-memory service wiring the section 6 endpoints.
"""
