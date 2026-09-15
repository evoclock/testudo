# Task 106 deferred live validation

These items cannot be proven by the macOS unit-test environment. They remain required before Task 106 is complete.

## Linux Firecracker gate

- Boot the exact approved Testudo commit with Firecracker 1.16.1 on `linux-backend`.
- Verify the real UDS `CONNECT <port>` / `OK <port>` exchange and guest AF_VSOCK accept path.
- Verify the root filesystem is mounted read-only with the pinned kernel and rootfs.
- Verify the guest image starts `testudo_contained_guest.sh` as PID 1 and contains byte-matched monitor, taxonomy, bootstrap, and supervisor artifacts.
- Verify containment watcher behavior using the guest's actual BusyBox/GNU toolset, including timestamp-baseline behavior and `/tmp` detection.
- Exercise crash/restart recovery, admitted-only and started runs, terminalization, quarantine reconciliation, and prevention of duplicate launch.

## Apple native-container gate

- Build the pinned `Dockerfile.native-smoke` recipe with Apple's native container runtime, not Docker or Podman.
- Verify bind-mount target creation under the read-only root and UID/GID 65532.
- Verify supervisor startup, taxonomy digest, watcher activation, stdio framing, containment receipt, revocation, and wipe.
- Confirm the CLI options used by `build_native_container_argv` match the installed Apple runtime.

## Artifact and provenance gate

Every downloaded or generated binary, dependency, kernel, rootfs, initramfs, guest bundle, and image must be pinned or content-addressed. Record its locally recomputed SHA-256, source provenance, timezone-aware verification time, and exact approved 40-hex Testudo commit in `testudo.artifact.manifest.v1`. No floating `latest` references are allowed.

## Deferred hardening

- Replace lexical shell path canonicalization with filesystem-aware, symlink-safe containment where the admitted guest toolset supports it. Until then, live tests must prove that symlink targets are also covered by swept roots.
- Consider splitting the overloaded `IsolationProfile.primitive == "docker"` value into a distinct native-container primitive. Current assignment routing remains backend-closed and does not invoke Docker, but the type name is misleading.
- Correlating oversized JSON frames would require bounded prefix parsing. Current behavior safely refuses them with a null request ID.
