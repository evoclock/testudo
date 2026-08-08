# Task 37 final-fix implementation grouping

Status: implementation record only. **Nothing in this repository has been
committed, pushed, or tagged by this work.** Every change below sits in the
working tree alongside the pre-existing uncommitted Task 106 work, which was
preserved untouched.

## Scope attribution

The following working-tree areas are **Task 106 scope, not Task 37**. They
were present as uncommitted changes before this Task 37 pass began and were
left byte-identical by it:

- Firecracker handshake/rootfs binding: `src/testudo/runtime/firecracker.py`
  (`rootfs_format`, `resolved_boot_args`, read-only root drive boot-args
  validation) and `src/testudo/runtime/firecracker_adapter.py`.
- Protocol rename: the `testudo.vsock.frame.v1` / stdio guest-mode naming now
  used across `src/testudo/runtime/native_container.py`,
  `guest/testudo_guest_smoke.py`, and `guest/testudo_guest_bootstrap.py`.
- Docker fail-closed: `src/testudo/runtime/docker.py` refusing an unenforced
  `network_policy` on the compatibility backend.
- Governed native config: the governed Runner construction seam and native
  adapter configuration in `src/testudo/runtime/host_runtime.py`,
  `src/testudo/runtime/isolation.py`, and `src/testudo/runtime/runner.py`
  (authorization plumbing predating this pass).
- Guest stdio changes: `guest/testudo_guest_smoke.py` stdio listener mode and
  the bootstrap's stdio/vsock mode split.

Task 37 scope (this pass) is limited to:

- `src/testudo/runtime/assignment_protocol.py` — M1, L1, L3/L4, L2 protocol
  surface.
- `src/testudo/runtime/assignment.py` — M2, L2 service surface.
- `src/testudo/runtime/runner.py` — L6 receipt reset ordering.
- `src/testudo/runtime/policy.py` and
  `src/testudo/runtime/native_container.py` — L5 whitespace rejection.
- `guest/testudo_containment_monitor.sh` and
  `guest/testudo_contained_guest.sh` — M3 sweep and L8 canonicalization.
- `Dockerfile.native-smoke` — L7 supervisor chain install.
- Tests: `tests/test_assignment_protocol.py`, `tests/test_assignment.py`,
  `tests/test_containment_monitor.py`, `tests/test_runner.py`,
  `tests/test_native_container.py`, `tests/test_policy.py`,
  `tests/test_native_smoke_image.py` (new).

## Coherent commit grouping proposal (not executed)

1. `fix(assignment-protocol): correlate framed errors and canonicalize nonce
   ordering` — M1 + L1 with their protocol tests.
2. `fix(assignment): fail closed on quarantine collision and rename failure`
   — M2 with its ambiguity-marker tests.
3. `feat(assignment): operator terminalization for recovered interrupted
   runs` — L2 service + protocol operation with tests.
4. `fix(protocol): one active session secret with rotation and revocation` —
   L3/L4 with the secret-lifecycle tests.
5. `fix(policy): reject whitespace in declared guest paths` — L5 with the
   policy and native-container tests.
6. `fix(runner): reset host receipt under the run lock` — L6 with the race
   regression test.
7. `fix(containment): sweep /tmp outside the session and canonicalize
   writable paths` — M3 + L8 with the monitor/supervisor tests.
8. `fix(native-smoke): install the guest supervisor chain` — L7 with the
   static contract test.
9. `docs: record Task 37 grouping and artifact-pinning requirements` — this
   document.

Groups 1–8 are independently revertible; each carries its own tests. The
Task 106 areas above belong to their own commit series authored under Task
106 authority and are excluded from every group here.

## Linux-backend later: artifact pinning and provenance (documentation only)

Every download or generated artifact used by the Linux backend (Firecracker
binary, kernel image, rootfs, guest initramfs, controller bundle) must be:

- **Pinned or content-addressed** — referenced by an exact content digest
  (SHA-256) or an immutable version; a floating `latest` reference is
  forbidden in any admitted configuration.
- **Checksum-verified** — the digest recorded in the run's admission contract
  is recomputed from the artifact bytes before any launch; a mismatch fails
  closed.
- **Provenance-recorded** — the manifest entry records the artifact source
  URL, the digest, the verification timestamp, and the exact approved Testudo
  commit the artifact was recorded against.

To support this without any remote access now, the manifest contract lives in
`src/testudo/runtime/artifact_manifest.py` (new, stdlib-only): a closed
schema for artifact manifest entries plus a validator that rejects floating
references and digest-shape violations. The Linux-backend work later records
entries against the exact approved commit; nothing is downloaded or fetched
by this module.
