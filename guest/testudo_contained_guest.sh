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

# The fixed no-network profile is host-enforced. This watcher turns any
# workload-created TCP or UDP socket into immediate denial evidence, using a
# baseline-then-flag sweep: BEFORE arming, the socket identities already
# present in the guest image (its own sshd listener, etc.) are snapshotted
# into the supervisor variable NET_BASELINE and skipped at sweep time; every
# socket identity NOT in the baseline is GC-NET-001 evidence. Semantics (see
# gc_net_sweep in the monitor): the snapshot is point-in-time before the
# workload starts, so an agent cannot pre-create a socket into the baseline;
# identity is local:remote:inode (fields $2:$3:$10) — the sl slot column and
# queue/timer fields churn, so full rows are never compared; a socket that
# closes and reopens after arming has a new kernel inode and therefore a
# different identity, so the same local:remote tuple re-listed with a
# different inode IS flagged (correct: it is a new socket). The baseline is
# a SUPERVISOR SHELL VARIABLE, deliberately not a file: the containment state
# dir is PRUNED by the fs sweep (not inspected by it), so a baseline file
# there would be agent-writable and tamperable — a workload could append its
# own /proc row and whitelist itself; no agent-writable baseline artifact
# exists. An empty baseline fails closed: every socket is flagged.
NET_BASELINE=$(for table in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do
  [ -r "$table" ] || continue
  awk 'NR > 1 && $2 !~ /:0000$/ {print $2":"$3":"$10}' "$table"
done | sort | uniq)
if [ -z "$NET_BASELINE" ]; then
  echo "testudo: net baseline is empty; the net sweep will fail closed (every socket flagged)" >&2
fi

net_watch() {
  while [ ! -f "$state/stop" ] && [ ! -f "$state/kill" ]; do
    # Baseline filtering happens here, before gc_net_detect: the monitor's
    # gc_net_detect signature and behavior are unchanged.
    gc_net_sweep "$state" "$NET_BASELINE" /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6
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
