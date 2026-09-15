# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Host-supervisor-owned construction for governed Testudo runners.

This module is a construction seam, not an authority store.  The host
supervisor supplies a per-run authorization provider backed by the canonical
lease/approval gate, plus explicit token-revocation and VM-wipe callbacks.
Testudo never reads or invents lease authority here.  Building the object
creates no process, listener, credential, network grant, or VM.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from testudo.runtime.backend import ExecutionBackend
from testudo.runtime.firecracker_adapter import FirecrackerAdapter
from testudo.runtime.native_container import NativeContainerAdapter, NativeProcess
from testudo.runtime.runner import Runner, RunnerAuthorizationProvider, RunnerController
from testudo.runtime.signing import TokenSigner

_HEX_DIGEST = re.compile(r"^[0-9a-f]{40,64}$")


@dataclass(frozen=True, slots=True)
class GovernedRunnerConfig:
    """Explicit inputs needed to construct one governed microVM Runner.

    ``authorization_provider`` must validate the current lease and trusted
    approval source for each run ID and return fresh, run-bound authority.
    ``revoke_token`` and ``wipe_vm`` are mandatory because Testudo cannot
    safely infer either operation from a path or environment variable.
    """

    runs_root: Path
    firecracker_binary: Path
    host_id: str
    repository: str
    branch: str
    base_sha: str
    authorization_provider: RunnerAuthorizationProvider
    revoke_token: Callable[[str], None]
    wipe_vm: Callable[[], None]
    signing_key: bytes | None = None
    signer: TokenSigner | None = None
    artifact_digest: str | None = None
    startup_timeout: float = 5.0
    boot_args: str = "console=ttyS0 reboot=k panic=1 pci=off"
    vcpu_count: int | None = None
    mem_size_mib: int | None = None

    def __post_init__(self) -> None:
        runs_root = Path(self.runs_root)
        binary = Path(self.firecracker_binary)
        object.__setattr__(self, "runs_root", runs_root)
        object.__setattr__(self, "firecracker_binary", binary)
        if not all(
            isinstance(value, str) and value
            for value in (self.host_id, self.repository, self.branch, self.base_sha)
        ):
            raise ValueError("host identity, repository, branch and base_sha are required")
        if not self.branch.startswith("agent/"):
            raise ValueError("governed Runner branches must start with agent/")
        if _HEX_DIGEST.fullmatch(self.base_sha) is None:
            raise ValueError("base_sha must be a lowercase 40-64 character object digest")
        if not callable(self.authorization_provider):
            raise ValueError("authorization_provider is required")
        if not callable(self.revoke_token) or not callable(self.wipe_vm):
            raise ValueError("revoke_token and wipe_vm callbacks are required")
        if (self.signing_key is None) == (self.signer is None):
            raise ValueError("exactly one capability-token verifier is required")
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise ValueError(f"executable Firecracker binary is required: {binary}")
        if self.startup_timeout <= 0:
            raise ValueError("startup_timeout must be positive")
        if self.vcpu_count is not None and self.vcpu_count < 1:
            raise ValueError("vcpu_count must be positive")
        if self.mem_size_mib is not None and self.mem_size_mib < 128:
            raise ValueError("mem_size_mib is below the safe minimum")

    def build_runner(self) -> Runner:
        """Construct the Runner without starting any runtime infrastructure."""
        adapter = FirecrackerAdapter(
            self.firecracker_binary,
            runs_root=self.runs_root,
            host_id=self.host_id,
            repository=self.repository,
            branch=self.branch,
            base_sha=self.base_sha,
            signing_key=self.signing_key,
            signer=self.signer,
            revoke_token=self.revoke_token,
            wipe_vm=self.wipe_vm,
            artifact_digest=self.artifact_digest,
            startup_timeout=self.startup_timeout,
            boot_args=self.boot_args,
            vcpu_count=self.vcpu_count,
            mem_size_mib=self.mem_size_mib,
        )
        return Runner(
            self.runs_root,
            backend=ExecutionBackend.MICROVM,
            microvm_controller=adapter,
            authorization_provider=self.authorization_provider,
        )


@dataclass(frozen=True, slots=True)
class GovernedNativeContainerRunnerConfig:
    """Explicit inputs for one governed Apple native-container Runner.

    Construction verifies the platform and executable but does not launch a
    process. Local image admission is mandatory so Apple's CLI cannot turn a
    missing image into an implicit network pull.
    """

    runs_root: Path
    container_binary: Path
    authorization_provider: RunnerAuthorizationProvider
    image_exists: Callable[[str], bool]
    revoke_token: Callable[..., None]
    wipe_container: Callable[..., None]
    max_output_bytes: int = 4 * 1024 * 1024
    stop_timeout: float = 5.0

    def __post_init__(self) -> None:
        runs_root = Path(self.runs_root)
        binary = Path(self.container_binary).resolve()
        object.__setattr__(self, "runs_root", runs_root)
        object.__setattr__(self, "container_binary", binary)
        if sys.platform != "darwin":
            raise ValueError("native-container governed runners require macOS")
        if binary.name != "container" or not binary.is_file() or not os.access(binary, os.X_OK):
            raise ValueError(f"executable Apple container binary is required: {binary}")
        if not callable(self.authorization_provider):
            raise ValueError("authorization_provider is required")
        if not callable(self.image_exists):
            raise ValueError("local image admission callback is required")
        if not callable(self.revoke_token) or not callable(self.wipe_container):
            raise ValueError("revoke_token and wipe_container callbacks are required")
        if self.max_output_bytes <= 0 or self.max_output_bytes > 4 * 1024 * 1024:
            raise ValueError("max_output_bytes is outside the stdio limit")
        if self.stop_timeout <= 0:
            raise ValueError("stop_timeout must be positive")

    def build_runner(self) -> Runner:
        """Construct the native Runner without launching Apple container."""
        binary = self.container_binary

        def invoke_container(argv: Sequence[str], **kwargs: Any) -> NativeProcess:
            if not argv or argv[0] != "container":
                raise ValueError("native container argv does not target the admitted container CLI")
            process = subprocess.Popen([str(binary), *argv[1:]], **kwargs)
            return cast(NativeProcess, process)

        adapter = NativeContainerAdapter(
            popen=invoke_container,
            max_output_bytes=self.max_output_bytes,
            stop_timeout=self.stop_timeout,
            image_exists=self.image_exists,
            revocation_hook=self.revoke_token,
            wipe_hook=self.wipe_container,
        )
        return Runner(
            self.runs_root,
            backend=ExecutionBackend.NATIVE_CONTAINER,
            native_container_controller=cast(RunnerController, adapter),
            authorization_provider=self.authorization_provider,
        )


def build_governed_runner(
    config: GovernedRunnerConfig | GovernedNativeContainerRunnerConfig,
) -> Runner:
    """Build an explicitly selected governed Runner; never choose a fallback."""
    if not isinstance(config, (GovernedRunnerConfig, GovernedNativeContainerRunnerConfig)):
        raise TypeError("unsupported governed Runner configuration")
    return config.build_runner()


__all__ = [
    "GovernedNativeContainerRunnerConfig",
    "GovernedRunnerConfig",
    "build_governed_runner",
]
