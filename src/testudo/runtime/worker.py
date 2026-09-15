# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Fail-closed lifecycle binding between Firecracker and capability policy."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol

from testudo.runtime.capability import (
    CapabilityToken,
    SupervisorEvent,
    WorkerSupervisor,
    WorkerTerminated,
)
from testudo.runtime.signing import TokenSigner


class ProcessHandle(Protocol):
    """Subset of a host process handle needed by the lifecycle controller."""

    def poll(self) -> int | None:
        """Return the exit status, or ``None`` while the process runs."""


class VMHandle(Protocol):
    """Process/socket operations required from a host VM adapter."""

    process: ProcessHandle

    def terminate(self, *, timeout: float = 5.0) -> None:
        """Terminate the guest process tree."""

    def cleanup(self) -> None:
        """Remove adapter-owned sockets and transient host state."""


class WorkerLifecycle:
    """Bind token expiry and tripwires to one Firecracker VM handle.

    The lifecycle object is deliberately host-side.  The worker can request
    only capabilities checked by :class:`WorkerSupervisor`; it cannot revoke,
    renew, or widen its own token.  Every terminal path revokes the token,
    removes adapter-owned sockets, and invokes the host wipe callback.
    """

    def __init__(
        self,
        handle: VMHandle,
        token: CapabilityToken,
        *,
        signing_key: bytes | None = None,
        signer: TokenSigner | None = None,
        revoke_token: Callable[[str], None],
        wipe_vm: Callable[[], None],
        event_sink: Callable[[SupervisorEvent], None] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.handle = handle
        self._revoke = revoke_token
        self._wipe = wipe_vm
        self._closed = False
        self._revoked = False
        self._wiped = False
        self._events = event_sink or (lambda _event: None)
        self._now = now or (lambda: datetime.now(UTC))
        self._supervisor = WorkerSupervisor(
            token,
            signing_key=signing_key,
            signer=signer,
            kill_vm=self._kill_vm,
            wipe_vm=self._wipe_vm,
            revoke_token=self._revoke_once,
            event_sink=self._events,
            now=self._now,
        )

    @property
    def supervisor(self) -> WorkerSupervisor:
        """Expose policy checks without exposing a token issuer."""
        return self._supervisor

    @property
    def closed(self) -> bool:
        """Whether the worker has reached a terminal lifecycle state."""
        return self._closed

    def check(self) -> None:
        """Check token validity and trip the VM on expiry."""
        try:
            self._supervisor.check_expiry()
        except WorkerTerminated:
            self._closed = True
            raise

    def stop(self, reason: str = "operator_stop") -> SupervisorEvent:
        """Revoke, terminate, clean up, and wipe the VM for an explicit stop."""
        event = self._supervisor.trip(reason)
        self._closed = True
        return event

    def wait(self, *, timeout: float | None = None, poll_interval: float = 0.05) -> int:
        """Supervise until exit, expiry, or timeout and return the exit status."""
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        if self._closed:
            raise WorkerTerminated("worker lifecycle is closed")
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            try:
                self.check()
            except WorkerTerminated:
                self._closed = True
                raise
            status = self.handle.process.poll()
            if status is not None:
                self._finish(status)
                return status
            if deadline is not None and time.monotonic() >= deadline:
                self._supervisor.trip("worker_timeout")
                self._closed = True
                raise WorkerTerminated("worker timeout")
            time.sleep(poll_interval)

    def _kill_vm(self) -> None:
        """Terminate the VM and always remove its adapter-owned sockets."""
        try:
            self.handle.terminate()
        finally:
            self.handle.cleanup()

    def _wipe_vm(self) -> None:
        """Wipe ephemeral state once, then clean up adapter-owned sockets."""
        if self._wiped:
            return
        self._wiped = True
        try:
            self._wipe()
        finally:
            self.handle.cleanup()

    def _revoke_once(self, token_id: str) -> None:
        """Make token revocation idempotent across all terminal paths."""
        if self._revoked:
            return
        self._revoked = True
        self._revoke(token_id)

    def _finish(self, status: int) -> None:
        """Revoke and wipe after a host-observed normal or failed exit."""
        if self._closed:
            return
        try:
            self.handle.cleanup()
        finally:
            self._revoke_once(self._supervisor.token.token_id)
            self._wipe_vm()
            self._events(
                SupervisorEvent(
                    event="worker_exit",
                    reason=f"exit_status:{status}",
                    token_id=self._supervisor.token.token_id,
                    at=self._now().astimezone(UTC).isoformat().replace("+00:00", "Z"),
                )
            )
            self._closed = True


__all__ = ["ProcessHandle", "VMHandle", "WorkerLifecycle"]
