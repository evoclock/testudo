from datetime import UTC, datetime, timedelta

import pytest

from testudo.runtime.capability import CapabilityToken, WorkerTerminated
from testudo.runtime.worker import WorkerLifecycle

NOW = datetime(2026, 8, 8, 12, 0, tzinfo=UTC)


class FakeProcess:
    def __init__(self, status: int | None = None) -> None:
        self.status = status

    def poll(self) -> int | None:
        return self.status


class FakeVM:
    def __init__(self, process: FakeProcess | None = None) -> None:
        self.process = process or FakeProcess()
        self.terminated = 0
        self.cleaned = 0

    def terminate(self, *, timeout: float = 5.0) -> None:
        del timeout
        self.terminated += 1
        self.process.status = -15

    def cleanup(self) -> None:
        self.cleaned += 1


def make_token(*, lifetime: timedelta = timedelta(minutes=10)) -> CapabilityToken:
    return CapabilityToken.issue(
        signing_key=b"host-secret",
        run_id="run-1",
        lease_id="lease-1",
        host_id="mac-mini",
        vm_id="vm-1",
        repository="testudo-agents",
        branch="agent/T-0254/run-1",
        base_sha="a" * 40,
        capabilities=("export",),
        allowed_paths=("agents/checkpoints/",),
        lifetime=lifetime,
        now=NOW,
    )


def lifecycle(
    vm: FakeVM,
    *,
    now: datetime = NOW,
    lifetime: timedelta = timedelta(minutes=10),
) -> tuple[WorkerLifecycle, list[str], list[str], list[object]]:
    calls: list[str] = []
    wipes: list[str] = []
    events: list[object] = []
    controller = WorkerLifecycle(
        vm,
        make_token(lifetime=lifetime),
        signing_key=b"host-secret",
        revoke_token=lambda token_id: calls.append(f"revoke:{token_id}"),
        wipe_vm=lambda: wipes.append("wipe"),
        event_sink=events.append,
        now=lambda: now,
    )
    return controller, calls, wipes, events


def test_stop_revokes_terminates_cleans_and_wipes_once() -> None:
    vm = FakeVM()
    controller, calls, wipes, events = lifecycle(vm)

    event = controller.stop("human_stop")
    controller.stop("duplicate_stop")

    assert event.event == "worker_trip"
    assert event.reason == "human_stop"
    assert vm.terminated == 1
    assert vm.cleaned == 2  # kill path plus wipe path
    assert wipes == ["wipe"]
    assert len(calls) == 1
    assert controller.closed
    assert events == [event]


def test_expiry_trips_the_bound_vm() -> None:
    vm = FakeVM()
    controller, calls, wipes, _events = lifecycle(
        vm, now=NOW + timedelta(seconds=1), lifetime=timedelta(seconds=1)
    )

    with pytest.raises(WorkerTerminated, match="expired"):
        controller.check()

    assert vm.terminated == 1
    assert vm.cleaned == 2
    assert wipes == ["wipe"]
    assert len(calls) == 1
    assert controller.closed


def test_timeout_trips_the_bound_vm() -> None:
    vm = FakeVM()
    controller, calls, wipes, events = lifecycle(vm)

    with pytest.raises(WorkerTerminated, match="timeout"):
        controller.wait(timeout=0, poll_interval=0.01)

    assert vm.terminated == 1
    assert vm.cleaned == 2
    assert wipes == ["wipe"]
    assert len(calls) == 1
    assert controller.closed
    assert events[0].reason == "worker_timeout"


def test_destructive_host_request_trips_the_bound_vm() -> None:
    vm = FakeVM()
    controller, calls, wipes, _events = lifecycle(vm)

    with pytest.raises(WorkerTerminated, match="host-boundary"):
        controller.supervisor.request("export", target="host", destructive=True)

    assert vm.terminated == 1
    assert vm.cleaned == 2
    assert wipes == ["wipe"]
    assert len(calls) == 1


def test_normal_exit_revokes_cleans_wipes_and_records_exit() -> None:
    vm = FakeVM(FakeProcess(status=7))
    controller, calls, wipes, events = lifecycle(vm)

    assert controller.wait(timeout=1) == 7

    assert vm.terminated == 0
    assert vm.cleaned == 2  # finish path plus wipe path
    assert wipes == ["wipe"]
    assert len(calls) == 1
    assert controller.closed
    assert events[0].event == "worker_exit"
    assert events[0].reason == "exit_status:7"


def test_wait_rejects_non_positive_poll_interval() -> None:
    controller, _calls, _wipes, _events = lifecycle(FakeVM())

    with pytest.raises(ValueError, match="poll_interval"):
        controller.wait(poll_interval=0)
