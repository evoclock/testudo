# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Normative shell scripts from docs/SEAT_CONTROL_SPEC.md (Revision 5).

Byte-exact constants embedded at generation time from the spec and pinned
by SHA-256 digest. tests/seat/test_normative_scripts.py re-derives the
scripts from the spec via the fixture harness extractor and asserts the
digests match, so a spec change cannot silently desynchronize production.

C2 (spec 3.2): every remote invocation renders one of these constants via
remote_command(script, args); no user value is ever concatenated into a
script body.
"""

from __future__ import annotations

import hashlib

EXEC_V1: str = 'set -eu; exec "$@"'

GUARD_V1: str = 'set -eu\nfor x in flock stat timeout; do\n  command -v "$x" >/dev/null 2>&1 || { printf \'TESTUDO_GUARD_UNAVAILABLE %s\\n\' "$x"; exit 73; }\ndone\numask 077\nd="$HOME/.testudo"\nif [ -L "$d" ]; then printf \'%s\\n\' TESTUDO_GUARD_UNSAFE; exit 74; fi\nif [ ! -e "$d" ]; then mkdir -m 700 -- "$d"; fi\n[ -d "$d" ] && [ ! -L "$d" ] || { printf \'%s\\n\' TESTUDO_GUARD_UNSAFE; exit 74; }\n[ "$(stat -c \'%u:%a\' -- "$d")" = "$(id -u):700" ] || { printf \'%s\\n\' TESTUDO_GUARD_UNSAFE; exit 74; }\nlock="$d/$1"; nonce="$2"; shift 2\nif [ -e "$lock" ] && { [ -L "$lock" ] || [ ! -f "$lock" ]; }; then printf \'%s\\n\' TESTUDO_GUARD_UNSAFE; exit 74; fi\n: >>"$lock"; chmod 600 -- "$lock"\n[ "$(stat -c \'%u:%a\' -- "$lock")" = "$(id -u):600" ] || { printf \'%s\\n\' TESTUDO_GUARD_UNSAFE; exit 74; }\nexec 9<>"$lock"\nflock --exclusive --wait 10 9 || { printf \'%s\\n\' TESTUDO_GUARD_BUSY; exit 75; }\nprintf \'TESTUDO_LOCKED %s\\n\' "$nonce"\ngate=$(timeout 30 head -n 1) || { printf \'%s\\n\' TESTUDO_GATE_TIMEOUT; exit 76; }\n[ "$gate" = "GO $nonce" ] || { printf \'%s\\n\' TESTUDO_GATE_REFUSED; exit 77; }\nset +e\n"$@" 9>&- </dev/null\nrc=$?\nset -e\nprintf \'\\nTESTUDO_OPERATION_EXIT %s %s\\n\' "$nonce" "$rc"\nrelease=$(timeout 1830 head -n 1) || { printf \'%s\\n\' TESTUDO_RELEASE_TIMEOUT; exit 76; }\n[ "$release" = "RELEASE $nonce" ] || { printf \'%s\\n\' TESTUDO_GATE_REFUSED; exit 77; }\nexit "$rc"\n'

LAUNCH_V1: str = 'set -eu\nfor x in nohup setsid stat sha256sum sleep; do command -v "$x" >/dev/null 2>&1 || exit 78; done\ncwd=$1; seat=$2; expected=$3; shift 3\nlogs="$HOME/.testudo/logs"\n[ ! -L "$logs" ] || exit 78\nif [ ! -e "$logs" ]; then mkdir -m 700 -- "$logs"; fi\n[ -d "$logs" ] && [ ! -L "$logs" ] || exit 78\n[ "$(stat -c \'%u:%a\' -- "$logs")" = "$(id -u):700" ] || exit 78\nlog="$logs/$seat.log"\nif [ -e "$log" ] && { [ -L "$log" ] || [ ! -f "$log" ]; }; then exit 78; fi\n: >"$log"; chmod 600 -- "$log"\n[ "$(stat -c \'%u:%a\' -- "$log")" = "$(id -u):600" ] || exit 78\nif [ -n "$cwd" ]; then cd -- "$cwd"; fi\nnohup setsid -- "$@" >"$log" 2>&1 </dev/null &\npid=$!\ni=0\nwhile [ "$i" -lt 20 ]; do\n  if [ -r "/proc/$pid/stat" ] && [ -r "/proc/$pid/cmdline" ] && [ -r /proc/sys/kernel/random/boot_id ]; then\n    statline=$(cat "/proc/$pid/stat")\n    rest=${statline##*) }\n    if [ "$rest" != "$statline" ]; then\n      set -- $rest\n      if [ "$#" -ge 20 ]; then\n        live_pgid=$3; shift 19; live_start=$1\n        live_hash=$(sha256sum "/proc/$pid/cmdline"); live_hash=${live_hash%% *}\n        boot=$(cat /proc/sys/kernel/random/boot_id)\n        if [ "$live_pgid" = "$pid" ] && [ "$live_hash" = "$expected" ]; then\n          printf \'TESTUDO_PID %s %s %s %s %s\\n\' "$pid" "$live_pgid" "$live_start" "$boot" "$live_hash"\n          exit 0\n        fi\n      fi\n    fi\n  fi\n  sleep 0.1; i=$((i + 1))\ndone\nexit 78\n'

C_PID_V1: str = 'set -eu\nfor x in stat sha256sum sleep; do command -v "$x" >/dev/null 2>&1 || exit 79; done\nmode=$1; pid=$2; pgid=$3; expected_start=$4; expected_boot=$5; expected_hash=$6\nverify() {\n  [ -r "/proc/$pid/stat" ] || return 1\n  [ -r "/proc/$pid/cmdline" ] || return 1\n  [ -r /proc/sys/kernel/random/boot_id ] || return 2\n  [ "$(cat /proc/sys/kernel/random/boot_id)" = "$expected_boot" ] || return 2\n  statline=$(cat "/proc/$pid/stat") || return 1\n  rest=${statline##*) }\n  [ "$rest" != "$statline" ] || return 2\n  set -- $rest; [ "$#" -ge 20 ] || return 2\n  live_pgid=$3; shift 19; live_start=$1\n  live_hash=$(sha256sum "/proc/$pid/cmdline") || return 1\n  live_hash=${live_hash%% *}\n  [ "$live_pgid" = "$pgid" ] && [ "$live_pgid" = "$pid" ] || return 2\n  [ "$live_start" = "$expected_start" ] && [ "$live_hash" = "$expected_hash" ] || return 2\n}\nverify || exit 79\nif [ "$mode" = inspect ]; then printf \'%s\\n\' TESTUDO_PID_MATCH; exit 0; fi\n[ "$mode" = stop ] || exit 79\nkill -TERM -"$pgid"\ni=0\nwhile [ "$i" -lt 100 ]; do\n  v=0; verify || v=$?\n  if [ "$v" -eq 2 ]; then exit 79; fi\n  if [ "$v" -eq 1 ]; then exit 0; fi\n  sleep 0.1; i=$((i + 1))\ndone\nv=0; verify || v=$?\nif [ "$v" -eq 2 ]; then exit 79; fi\nif [ "$v" -eq 1 ]; then exit 0; fi\nkill -KILL -"$pgid"\n'

LOG_TAIL_V1: str = 'set -eu\nfor x in stat tail; do command -v "$x" >/dev/null 2>&1 || exit 78; done\nseat=$1; logs="$HOME/.testudo/logs"; log="$logs/$seat.log"\n[ -d "$logs" ] && [ ! -L "$logs" ] || exit 78\n[ "$(stat -c \'%u:%a\' -- "$logs")" = "$(id -u):700" ] || exit 78\n[ -f "$log" ] && [ ! -L "$log" ] || exit 78\n[ "$(stat -c \'%u:%a\' -- "$log")" = "$(id -u):600" ] || exit 78\nexec tail -c 4096 -- "$log"\n'

EXPECTED_DIGESTS: dict[str, str] = {
    "GUARD_V1": "6653a21821d6f3dfdc32120f2ae35d9fe5e7420872eff16f24370ec54d0a1e9e",
    "LAUNCH_V1": "b81dbd058c5a6ae00db951fc60362565fc46604b0739a189ccec4db0e5e66239",
    "C_PID_V1": "7246beede3e472b2bbd0dae73ec05079869cc30f5bd392575cf833aceeaefaea",
    "LOG_TAIL_V1": "a152af6d6a8ad7f19a33572e31ff76a34187a9cb6c7668eafe456618edbb1283",
    "EXEC_V1": "81e844264933390cf63746bd9a90e514479dd1a7aa0b5eaf157f47c528bf6a69",
}


def digest_of(script_text: str) -> str:
    """SHA-256 of the UTF-8 bytes of a script constant."""
    return hashlib.sha256(script_text.encode("utf-8")).hexdigest()


def verify_pins() -> dict[str, tuple[str, str]] | None:
    """Return {name: (actual, expected)} for drifted pins, or None."""
    drifted = {}
    for name, expected in EXPECTED_DIGESTS.items():
        actual = digest_of(globals()[name] if name != "EXEC_V1" else EXEC_V1)
        if actual != expected:
            drifted[name] = (actual, expected)
    return drifted or None
