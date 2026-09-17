"""Fixture systemctl / loginctl / ssh shims injected on the remote PATH.

SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later

Spec section 8 requires fixture systemctl and loginctl shims on PATH that
emulate unit states (activating/active/deactivating/failed), the
``systemctl --user`` verbs the spec uses with ActiveState/SubState/Result/
NRestarts/Restart properties, ``loginctl show-user`` Linger, and restart-loop
sequences. A scripted shim directory is uploaded to the fixture user's
``/opt/testudo-fixture/bin`` (already first on PATH via fixture-shell) by the
session fixture.

The shim is driven by a state file ``~/.fixture-state/systemd.json`` that
tests rewrite between SSH invocations; each invocation consumes one state
step, which is what makes restart-loop *sequences* (NRestarts increasing)
observable.
"""

from __future__ import annotations

import json
import textwrap

SHIM_DIR = "/opt/testudo-fixture/bin"
STATE_DIR = "$HOME/.fixture-state"

SYSTEMCTL_SHIM = textwrap.dedent(f"""\
    #!/bin/sh
    # Fixture systemctl shim (spec section 8). State-driven, sequence-aware.
    set -eu
    state_dir="{STATE_DIR}"
    state_file="$state_dir/systemd.json"
    step_file="$state_dir/step"
    [ -f "$state_file" ] || {{ echo "shim: no state" >&2; exit 90; }}
    step=$(cat "$step_file" 2>/dev/null || echo 0)
    python3 - "$state_file" "$step_file" "$step" "$@" <<'PYEOF'
    import json, os, sys
    state_file, step_file, step, argv = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4:]
    state = json.load(open(state_file))
    unit = None
    # Parse the exact argv shapes the spec's operation argv uses.
    if argv[:1] == ["--user"]:
        rest = argv[1:]
        verb = rest[0] if rest else "show"
        # collect the unit after '--'
        if "--" in rest:
            unit = rest[rest.index("--") + 1]
        props = [a.split("=", 1)[1] for a in rest if a.startswith("--property=")]
    else:
        verb, unit, props = "unknown", None, []
    seq = state["sequence"]
    if step >= len(seq):
        print("shim: state exhausted", file=sys.stderr); sys.exit(91)
    entry = seq[step]
    open(step_file, "w").write(str(step + 1))
    if verb in ("start", "stop", "kill"):
        # Destructive verbs: optionally hold the call open (controller-timeout
        # fixtures), then honour the scripted exit and emit nothing.
        import time
        time.sleep(float(entry.get("sleep", 0)))
        sys.exit(entry.get("exit", 0))
    if verb == "is-active":
        print(entry.get("active_state", "inactive"))
        sys.exit(0 if entry.get("active_state") == "active" else 3)
    if verb == "show":
        want = props or ["ActiveState", "SubState", "Result", "NRestarts", "Restart"]
        lines = []
        for key in want:
            if key not in entry:
                # Missing key -> the strict parser must call this invalid.
                print(f"shim: missing property {{key}}", file=sys.stderr); sys.exit(92)
            lines.append(f"{{key}}={{entry[key]}}")
        print("\\n".join(lines))
        sys.exit(0)
    if verb == "status":
        sys.exit(entry.get("status_exit", 0))
    print(f"shim: unsupported verb {{verb}}", file=sys.stderr); sys.exit(93)
    PYEOF
    """)

LOGINCTL_SHIM = textwrap.dedent(f"""\
    #!/bin/sh
    # Fixture loginctl shim (spec section 8 / U1).
    set -eu
    state_file="{STATE_DIR}/linger.json"
    [ -f "$state_file" ] || {{ echo "shim: no linger state" >&2; exit 90; }}
    python3 - "$state_file" "$@" <<'PYEOF'
    import json, sys
    state_file, argv = sys.argv[1], sys.argv[2:]
    state = json.load(open(state_file))
    # Expected shape: loginctl show-user <user> --property=Linger --value
    if argv and argv[0] == "show-user":
        if "--property=Linger" not in argv:
            print("shim: only Linger supported", file=sys.stderr); sys.exit(94)
        value = state.get("Linger")
        if value is None:
            # unknown: missing logind/user manager -> nonzero, no output
            sys.exit(95)
        if "--value" in argv:
            print(value)
        else:
            print(f"Linger={{value}}")
        sys.exit(0)
    print("shim: unsupported loginctl argv", file=sys.stderr); sys.exit(96)
    PYEOF
    """)

# A fake `ssh` binary on the remote PATH is NOT what G8 needs — G8 is about
# the *local* `ssh -G` resolution. The local shim lives in local_shims.py.
# What the remote does need is nothing extra: GUARD_V1 uses only flock/stat/
# timeout, LAUNCH_V1 uses nohup/setsid/stat/sha256sum/sleep, C_PID_V1 uses
# stat/sha256sum/sleep — all real in the Debian fixture.


def write_systemd_state(sequence: list[dict[str, object]]) -> str:
    """Return the JSON document for ~/.fixture-state/systemd.json."""
    return json.dumps({"sequence": sequence})


def write_linger_state(linger: str | None) -> str:
    """Return the JSON document for ~/.fixture-state/linger.json.

    ``None`` models a missing logind/user manager (loginctl exits 95 ->
    U1's ``unknown``). ``yes``/``no`` model the property values.
    """
    return json.dumps({"Linger": linger})
