# Seat-control fixture harness

SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later

Implementation of the mandatory first task from
`docs/SEAT_CONTROL_SPEC.md` (Revision 5), section 8: a fixture harness that
**executes every normative script exactly as written** and asserts the
behaviors section 7 claims. The seat-control production implementation is a
later task; this harness is its executable oracle.

Location rationale: `tests/seat_harness/` (not `tests/fixtures/seat/`) —
the spec says the harness "lives with the implementation" and runs in CI, so
it is a first-class test package, not a passive fixture directory.

## Running

```sh
# full harness (Docker present: Linux fixture; otherwise native macOS sshd)
pytest tests/seat_harness/ -q

# one group
pytest tests/seat_harness/test_g1_guard_fd9.py -q
```

CI-runnable (F8): the Docker fixture builds `FROM debian:12` — a public
Docker Hub base — with `openssh-server` and `python3` installed at build
time. No local-only base image is required. When Docker is present but the
fixture cannot be built or started (for example a runner without network
access), the whole harness **skips with an explicit reason** instead of
erroring, so a default `pytest -ra` job never hard-fails. Without Docker the
harness falls back to a native macOS sshd (see "Platform coverage" below).

Network use: the `debian:12` base pull (once, then cached) and the single
`apt-get install openssh-server python3` at image build time; plus loopback
SSH/HTTP for the fixtures themselves. No GPU, no real remote host.

## Components

| File | Role |
|---|---|
| `normative.py` | Extracts GUARD_V1, LAUNCH_V1, C_PID_V1, LOG_TAIL_V1 byte-exactly from the spec and pins their SHA-256 digests. Also extracts EXEC_V1 from the spec prose (`constant \`EXEC_V1\` is \`set\n-eu; exec "$@"\`` — the line break inside the identifier is a spec typo), asserts the raw fragment byte-for-byte, normalizes it to `set -eu; exec "$@"`, and pins that digest too. A spec change fails the pins first. |
| `render.py` | Reference C2 renderer (`sq`, `render`, `remote_command`) + C1 validators + `argv_sha256` (each UTF-8 element followed by one NUL, final argument NUL-terminated). |
| `guard_client.py` | Reference L2 controller: consumes `TESTUDO_LOCKED <nonce>`, writes `GO <nonce>` only after the post-lock poll, parses only the last nonce-bound trailer (any protocol-shaped text after it fails closed), runs reconciliation while both locks are held, writes `RELEASE <nonce>` — and RELEASE is triggered only by the *exact nonce-bound trailer line* (never by output that merely contains the marker). |
| `docker_fixture.py` + `docker/` | Disposable Linux sshd in Docker (public `debian:12` base; `openssh-server` + `python3` installed at build time). Full lifecycle: build → run on a dedicated bridge network → exec-provision → teardown removes the container, the network, and the image ("everything is removed"). The fixture user's login shell is `fixture-shell`, an exec wrapper that puts the shim directory first on PATH. |
| `native_sshd.py` | macOS fallback: per-session `/usr/sbin/sshd -D` on 127.0.0.1 with dedicated keys. Used when Docker is absent. |
| `shims.py` | Source of the fixture `systemctl`/`loginctl` shims uploaded into the fixture PATH. State-file driven (`~/.fixture-state/*.json`), sequence-aware (each invocation consumes one step) so restart-loop *sequences* with increasing NRestarts are observable; destructive verbs support a scripted `sleep` for real controller-timeout tests. |
| `model_server.py` | Trivial HTTP `/v1/models` servers with configurable model id, latency, and failure modes: stop/hard-kill (connection refused), hang (timeout), malformed JSON, oversized (>1 MiB), wrong Content-Type. |
| `data/` | Fixture servers for Template C launches: foreground (`fixture_srv.py`), slow-exit on TERM (`fixture_srv_slow_exit.py`), TERM-ignoring (`fixture_srv_stubborn.py`). All invoked as `/usr/local/bin/python3 <script>` so `/proc/<pid>/cmdline` matches `launch_argv` byte-exactly (a shebang wrapper would replace argv[0] — see R-3). |
| `conftest.py` | Session-scoped disposable host (Docker preferred, native fallback — both populate every host field so platform-gated tests skip cleanly), shim installer, normative-script digest check. |

## Assertion groups (section 8 items 1–8)

* **G1** `test_g1_guard_fd9.py` — the Revision 4 FD-inheritance deadlock
  regression. A real Template C start (LAUNCH_V1 under GUARD_V1), then:
  `/proc/<pid>/fd` of the started server contains no FD 9; an immediate stop
  (C_PID_V1, executed as `sh -c` exactly as the C2 construction renders it)
  on the same lock succeeds in well under the 10 s flock wait; and a negative
  control (a descendant that deliberately flocks FD 9) makes the next
  controller BUSY after the full 10 s wait — proving the detector is real.
* **G2** `test_g2_pid_identity.py` — PID capture from the exact TESTUDO_PID
  line; `argv_sha256` equals both the byte-layout recomputation and the raw
  `sha256sum /proc/<pid>/cmdline`; PGID == pid (setsid invariant); stat field
  20 (start ticks) identity; boot_id shape; C_PID_V1 inspect = TESTUDO_PID_MATCH;
  TERM-then-KILL escalation against a TERM-ignoring server (KILL lands, process
  group gone, exit 0); wrong start-ticks (PID-reuse shape) refuses signaling
  with 79; and the amended post-TERM semantics regression — a fast-exiting
  (TERM-killed) process is exit 0 success, never the old 79 race.
* **G3** `test_g3_quoting.py` — 23 golden adversarial vectors (spaces, quotes,
  `$()`, backticks, semicolons, leading dashes, newlines, tabs, globs, pipes,
  redirects, `--`, `-`, Unicode, the sq() escape itself) round-trip through a
  real sshd byte-for-byte; local argv carries exactly one remote string.
* **G4** `test_g4_guards.py` — nonce-bound trailer parsing (wrong nonce, forged
  trailing markers, malformed rc, and protocol-shaped text after the candidate
  trailer all fail closed); BUSY under a held lock with exact 10 s flock-wait
  timing; acquisition success after release (no age takeover); gate refusal on
  controller EOF releases the guard without running the operation; GO with a
  wrong nonce → GATE_REFUSED (77); `TESTUDO_GUARD_UNAVAILABLE <tool>`/73 for
  each of flock/stat/timeout, driven by explicitly invoking
  `env PATH=<dir-with-the-other-two-tools> /bin/sh -c GUARD_V1 ...` (the
  fixture sshd has no AcceptEnv, so SetEnv is inert — the environment is set
  for the child sh, which genuinely fails `command -v`); symlinked
  `~/.testudo` → `TESTUDO_GUARD_UNSAFE`/74; forged
  `TESTUDO_OPERATION_EXIT` lines in operation output stay ordinary output and
  the genuine trailer still parses to the real rc.
* **G5** `test_g5_template_a.py` — exact Template A inspect argv; shim-driven
  activating→active, failed/Result, restart-loop (NRestarts increase), missing
  property → invalid-systemd-state; start/stop lifecycle under GUARD_V1;
  **a real controller-timeout test**: a stop whose remote execution outlives
  the controller timeout terminates only the local SSH process
  (indeterminate, exit None) while the remote guard survives (second
  controller waits the full flock window and gets BUSY); a stuck-deactivating
  inspection sequence models the 30 s stop-window indeterminate;
  **force-stop: the exact kill argv
  (`systemctl --user kill --signal=SIGKILL -- <unit>`) executed under a real
  guard through the full protocol**, plus the bridge-side confirmation-
  challenge contract as an explicitly labeled SIMULATION-ONLY test (the
  production R1 challenge API does not exist yet).
* **G6** `test_g6_template_b.py` — status exit-code protocol (0/1/other);
  exact operation argv `[script, subcommand]` under the guard and status via
  EXEC_V1; **the L3 ownership gate driven for real**: the controller acquires
  the remote lock, polls a REAL fixture model server, and a different sole
  occupant refuses the stop via EOF (GUARD_V1 exits 77) with the control
  script never invoked (invocation-marker proof); flipping the endpoint to
  the exact sole seat model permits the stop and the script runs exactly
  once, with bounded occupant display; stop timeout kills only the local SSH
  process (indeterminate) while the remote guard survives (second controller
  BUSY); Template B's no-force-stop/no-challenge shape is bridge-side API
  surface, covered as an explicitly labeled SIMULATION-ONLY test.
* **G7** `test_g7_lingering.py` — the exact U1 probe argv via EXEC_V1 against
  the loginctl shim; Linger yes/no/unknown mapping (missing user manager →
  unknown); `loginctl enable-linger` is rejected and absent from every probe
  argv (both real, via the shim); the start-gate/warning paths and the
  post-session poll serving decision are bridge-side controller logic with
  no production implementation yet — both explicitly labeled
  SIMULATION-ONLY (the post-session test's model server, kill, and polls are
  real; only the final decision rule is the local model).
* **G8** `test_g8_consent_drift.py` — real `ssh -G` (shell:false, 10 s
  timeout, 1 MiB cap) with ordered parse; canonical effective value binds
  options + binary path/version/byte-hash; port drift → "re-confirmation
  required"; edit-back restores the canonical value but consent still requires
  reconfirmation (S3 conservative rule); same-path/same-version binary
  replacement detected by byte hash; S3 digest recomputation is deterministic
  and every input change (lifetime, transport, fingerprint, seat order,
  policy version) changes it.
* **G9** `test_g9_log_tail.py` — LOG_TAIL_V1 executed over real SSH: exact
  `tail -c 4096` bound (suffix of a larger file; whole file when smaller);
  owner/mode enforcement (logs `<uid>:700`, log `<uid>:600`, root-owned
  variants refused with 78); symlink rejection at both the logs directory
  and the log file (never followed, no content leaked); missing/non-file log
  fails closed with 78.

## Platform coverage (F9, documented per section 8)

The Docker (Linux) fixture is the default and runs everything above. The
native macOS fallback (no Docker) supports, for real: G3 quoting round-trips,
G4 trailer parsing and the per-tool `TESTUDO_GUARD_UNAVAILABLE` test (it
exits before touching guard storage), G5's inspect-argv transport test,
G6's status exit-code protocol, and all of G8 (local `ssh -G`).

Everything else **skips with an explicit reason — it never errors**:

* Linux-only semantics (flock across processes, setsid, `/proc`, GNU
  `stat -c`, GNU `timeout`): G1, G2, G9, and the guard-dependent G4/G5/G6
  tests skip with a section 8 platform-boundary reason on the native backend.
* The `systemctl`/`loginctl` shims are provisioned only in the Docker image
  (login-shell PATH injection); shim-dependent G5/G7 tests skip on the
  native backend with an explicit reason.
* If Docker is present but the fixture cannot be built or started, the whole
  harness skips with the docker error as the reason (CI-safe, `-ra` visible).

## Known spec normalizations (pinned)

* **EXEC_V1 spec typo**: the spec line break inside the identifier
  (`set\n-eu; exec "$@"`) is asserted byte-for-byte from the spec prose and
  normalized to `set -eu; exec "$@"`; both the raw fragment and the
  normalized form's digest are pinned in `normative.py`.
* **C_PID_V1 Revision 5 amendment (dash kill + fast-exit race)**: the spec
  previously used `kill -TERM -- "-$pgid"`, which Debian dash rejects with
  `Illegal number: -` (exit 2) — bash accepts it, so `bash -c` invocations
  masked the defect. The spec now uses the single-dash form
  `kill -TERM -"$pgid"` (and `kill -KILL -"$pgid"` for the escalation),
  accepted by both dash and bash; `$pgid` is already a validated decimal, so
  `--` is unnecessary. The harness executes C_PID_V1 under `sh -c` exactly
  as the C2 construction renders it (dash on the Debian fixture). The stop
  loop's `verify` now distinguishes *absent* (return 1 — after TERM that is
  SUCCESS, the kill worked) from *identity mismatch* (return 2 — exit 79),
  eliminating the old fast-exit race where a successfully-killed
  fast-exiting process could exit 79. Both amendments are re-pinned.
* **`ssh -G` output**: OpenSSH 10.2 (macOS) emits no `remotecommand` key at
  all; the descriptor-level `RemoteCommand=none` enforcement is pinned at the
  invocation-descriptor level, and the drift test asserts the keys -G does
  emit. Linux CI OpenSSH may differ; the test asserts only keys guaranteed
  present.
* **LAUNCH_V1 assumes `~/.testudo` already exists** (GUARD_V1 creates it in
  the same operation) — true in the guarded flow, but a bare `LAUNCH_V1` run
  on a fresh home fails `mkdir -m 700` on the logs directory. Confirmed
  harmless in the guarded flow; noted for completeness.

## Simulation-only boundaries (honest labels, F5/F6/F7)

Bridge-side decision/API logic has no production implementation yet (the
seat-control bridge is a later task). Where the harness asserts such logic it
does so against a local model and the test name/docstring says so explicitly:

| Test | Real part | Simulated part |
|---|---|---|
| `test_g5_force_stop_challenge_contract_simulation_only` | — (kill argv covered for real in `test_g5_force_stop_kill_argv_under_guard`) | the R1 challenge issuance/binding/single-use contract |
| `test_g6_no_force_stop_challenge_simulation_only` | — | the R1 "Template B exposes no challenge" API shape |
| `test_g7_start_gate_and_warning_paths_simulation_only` | the linger probe feeding the gate (real, via shim) | the U1 start-gate decision + warning strings |
| `test_g7_post_session_poll_requirement_simulation_only` | model server, hard kill, D2-shaped polls | the final serving/not-serving decision rule |

Everything else in G1–G9 is executed for real against the fixture host, the
guard protocol, the shims, or a real local `ssh -G`.

## Reviewer scrutiny items

1. The `_parse_last_trailer` fail-closed rule: any `TESTUDO_*` line after the
   candidate trailer rejects the whole output — confirm this matches the
   intended reading of "malformed or additional protocol-shaped text after
   the candidate trailer fails closed". The RELEASE trigger in the stream
   loop now shares the same exact-line matcher (`_exact_trailer_rc`).
2. The dash `kill --` incompatibility is RESOLVED by the Revision 5 spec
   amendment (single-dash form; both TERM and KILL lines — the KILL line had
   the same dash defect and was amended too). Digest re-pinned.
3. The C_PID_V1 fast-exit race is RESOLVED by the Revision 5 spec amendment
   (verify distinguishes absent from mismatched; post-TERM disappearance is
   success). Covered by `test_g2_fast_exit_stop_is_success_not_race_79`.
4. The `systemctl`/`loginctl` shims are state-sequence-driven; the G5
   stuck-deactivating stop-window test models the 30 s inspection window with
   a state sequence (deterministic, fast), while the controller-timeout
   behavior (local SSH termination → indeterminate, remote guard survival →
   BUSY) is tested with real wall-clock timeouts in both G5 and G6.

## SSH/sshd setup (what the harness automates)

Docker path (default): `docker build` from `docker/Dockerfile`
(`debian:12` + `openssh-server` + `python3`), `docker run -d --network
testudo-seat-harness --entrypoint /usr/sbin/sshd ... -D -e` with a published
127.0.0.1 port, then `docker exec -u fixture` installs the session key into
`/home/fixture/.ssh/authorized_keys` (0600, `StrictModes`-clean) and the
harness connects with `ssh -i <key> -p <port> fixture@127.0.0.1`. Teardown
removes the container, the `testudo-seat-harness` network, and the built
image — everything the fixture created is gone; stale containers/networks
from crashed runs are cleaned at session start.

Native macOS path: `/usr/sbin/sshd -D -f <tmp>/sshd_config` on a free
127.0.0.1 port with a dedicated ed25519 host key and user key; state lives
entirely under the pytest tmp dir and is removed afterwards.
