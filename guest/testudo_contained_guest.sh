#!/bin/sh
# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-only

# PID-1-compatible supervisor for the Testudo workflow guest. The admitted
# image installs the monitor, taxonomy, bootstrap, and this script read-only.
set -eu

MONITOR=${TESTUDO_CONTAINMENT_MONITOR:-/opt/testudo/testudo_containment_monitor.sh}
BOOTSTRAP=${TESTUDO_GUEST_BOOTSTRAP:-/opt/testudo/testudo_guest_bootstrap.py}
TAXONOMY=${TESTUDO_CONTAINMENT_TAXONOMY:-/opt/testudo/guest_containment_taxonomy.v1.json}
STATE_ROOT=${TESTUDO_CONTAINMENT_STATE_ROOT:-/tmp/testudo-containment}
REAL_PATH=${TESTUDO_GUEST_REAL_PATH:-/usr/local/bin:/usr/bin:/bin}

[ -x "$MONITOR" ] || { echo "containment monitor missing" >&2; exit 70; }
[ -r "$BOOTSTRAP" ] || { echo "guest bootstrap missing" >&2; exit 70; }
[ -r "$TAXONOMY" ] || { echo "containment taxonomy missing" >&2; exit 70; }

# shellcheck source=testudo_containment_monitor.sh
. "$MONITOR"
actual_taxonomy_sha=$(sha256sum "$TAXONOMY" | awk '{print $1}')
[ "$actual_taxonomy_sha" = "$GC_TAXONOMY_SHA256" ] || {
  echo "containment taxonomy digest mismatch" >&2
  exit 70
}

session=${TESTUDO_RUN_ID:-guest-session}
state="$STATE_ROOT/$session"
# The declared workspace guest path comes from the admitted Testudo profile
# (the contract's workspace/guest_paths entry, exported by the host adapter
# through TESTUDO_GUEST_WORKSPACE). The monitor's writable allowlist is built
# from it; /tmp/session stays writable as the supervisor's own session scratch
# so containment state never trips the watcher.
WORKSPACE=${TESTUDO_GUEST_WORKSPACE:-/tmp/session}
export TESTUDO_GUEST_WORKSPACE="$WORKSPACE"
export TESTUDO_GUEST_WRITABLE_PATHS="$WORKSPACE /tmp/session"
mkdir -p "$state" "$WORKSPACE" /tmp/session
cp "$TAXONOMY" "$state/taxonomy.json"

# The fixed no-network profile is host-enforced. This watcher turns any TCP or
# UDP socket visible to the workload into immediate denial evidence.
net_watch() {
  while [ ! -f "$state/stop" ] && [ ! -f "$state/kill" ]; do
    for table in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do
      [ -r "$table" ] || continue
      awk 'NR > 1 && $2 !~ /:0000$/ {print $0}' "$table" | while IFS= read -r entry; do
        [ -n "$entry" ] && gc_net_detect "$state" "$entry" >/dev/null 2>&1 || true
      done
    done
    sleep 1
  done
}

# Writable storage is limited to the declared workspace plus the supervisor's
# own /tmp/session scratch. Any changed regular file outside those trees is
# classified and denied. The sweep covers /tmp itself: only the policy-allowed
# /tmp/session tree (and the supervisor's own containment state root) is
# exempt; any other /tmp write is outside-session evidence.
baseline="$state/fs-baseline"
touch "$baseline"
fs_watch() {
  while [ ! -f "$state/stop" ] && [ ! -f "$state/kill" ]; do
    for root in /agent /workspace /runs /var/cache /root /tmp; do
      [ -d "$root" ] || continue
      find "$root" -xdev \( -path "$state" -o -path "$state/*" \) -prune -o -type f -newer "$baseline" -print 2>/dev/null | while IFS= read -r path; do
        # Canonicalize before the exemption comparison: a traversal spelling
        # (/tmp/session/../evil) must never pass as session-scratch.
        case "$(gc_canonical_path "$path" 2>/dev/null || printf '%s' "$path")" in
          /tmp/session|/tmp/session/*) : ;; *) gc_fs_detect "$state" "$path" >/dev/null 2>&1 || true ;; esac
      done
    done
    gc_baseline_retreat "$baseline"
    sleep 1
  done
}

net_watch & net_pid=$!
fs_watch & fs_pid=$!

export TESTUDO_CONTAINMENT_ACTIVE="$actual_taxonomy_sha"
export PATH="$REAL_PATH"
python3 "$BOOTSTRAP" & guest_pid=$!

shutdown() {
  touch "$state/stop" 2>/dev/null || true
  kill "$net_pid" "$fs_pid" 2>/dev/null || true
  wait "$net_pid" "$fs_pid" 2>/dev/null || true
}
trap shutdown EXIT HUP INT TERM

while kill -0 "$guest_pid" 2>/dev/null; do
  if [ -f "$state/kill" ]; then
    kill -TERM "$guest_pid" 2>/dev/null || true
    sleep 1
    kill -KILL "$guest_pid" 2>/dev/null || true
    wait "$guest_pid" 2>/dev/null || true
    sync
    exit 126
  fi
  if ! kill -0 "$net_pid" 2>/dev/null || ! kill -0 "$fs_pid" 2>/dev/null; then
    gc_liveness "$state" "$(kill -0 "$net_pid" 2>/dev/null && printf 1 || printf 0) $(kill -0 "$fs_pid" 2>/dev/null && printf 1 || printf 0) 1" >/dev/null 2>&1 || true
    kill -TERM "$guest_pid" 2>/dev/null || true
    wait "$guest_pid" 2>/dev/null || true
    exit 126
  fi
  sleep 1
done

set +e
wait "$guest_pid"
status=$?
set -e
gc_session_end "$state"
exit "$status"
