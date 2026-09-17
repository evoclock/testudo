#!/bin/sh
# Testudo seat-control fixture harness — Linux remote fixture.
# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Holds the GUARD_V1 remote flock for a bounded time so the L2 BUSY and
# acquisition-timeout assertions have a real second controller. Invoked over
# SSH as: hold_guard.sh <seconds>
#
# It opens FD 9 on the same lock path GUARD_V1 uses and holds an exclusive
# flock, then prints HELD and sleeps. It releases on exit (fd close).
set -eu
secs=$1
d="$HOME/.testudo"
mkdir -p -m 700 -- "$d"
lock="$d/endpoint-deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef.lock"
: >>"$lock"
chmod 600 -- "$lock"
exec 9<>"$lock"
flock --exclusive 9
printf 'HELD\n'
sleep "$secs"
