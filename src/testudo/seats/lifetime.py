# SPDX-FileCopyrightText: 2026 Julen Gamboa <j.a.r.gamboa@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""U1 (lingering gate) and L4 (Linux remote platform prerequisites).

The lifetime probe uses ``remote_command(EXEC_V1, ["loginctl", "show-user",
effective_ssh_user, "--property=Linger", "--value"])``. Exactly one trimmed
value, ``yes`` or ``no``, is accepted; anything else is ``unknown``.
Testudo never runs ``loginctl enable-linger``.
"""

from __future__ import annotations

from dataclasses import dataclass

from testudo.seats._scripts import EXEC_V1
from testudo.seats.render import remote_command

LINGER_WARNING = "service may stop when this session ends"
SESSION_SLICE_WARNING = (
    "KillUserProcesses=yes or equivalent host policy can still terminate the "
    "process; the host-side script/launcher must place it in an appropriate "
    "persistent scope"
)
UNSUPPORTED_PLATFORM = "unsupported remote platform"

LINGER_PROBE_ARGV = ["loginctl", "show-user", "{user}", "--property=Linger", "--value"]


def linger_probe_remote_command(effective_ssh_user: str) -> str:
    """The exact U1 lifetime probe as a rendered remote command."""
    argv = [arg.replace("{user}", effective_ssh_user) for arg in LINGER_PROBE_ARGV]
    return remote_command(EXEC_V1, argv)


@dataclass(frozen=True)
class LingerObservation:
    value: str  # "yes" | "no" | "unknown"


def parse_linger_output(stdout: str, stderr: str, exit_code: int | None) -> LingerObservation:
    """Exactly one trimmed value, ``yes`` or ``no``, is accepted. Missing
    logind/user manager, failure, or any other output is ``unknown``."""
    if exit_code != 0:
        return LingerObservation("unknown")
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1 or lines[0] not in {"yes", "no"}:
        return LingerObservation("unknown")
    return LingerObservation(lines[0])


def start_gate(observation: LingerObservation) -> tuple[bool, str | None]:
    """U1: a start is enabled only when the immediately refreshed value is
    ``yes``; ``no`` or ``unknown`` refuses start as host lifetime
    prerequisite and displays the warning."""
    if observation.value == "yes":
        return True, None
    return False, LINGER_WARNING


# --- L4: per-template prerequisites -----------------------------------------

PREREQUISITES: dict[str, tuple[str, ...]] = {
    # R-2: loginctl/logind is a start prerequisite for ALL templates.
    "common": ("sh", "stat", "flock", "timeout", "loginctl"),
    "systemd-user": ("systemctl", "loginctl"),
    "control-script": (),
    "bare-command": ("setsid", "sha256sum", "nohup", "tail"),
}


def check_prerequisites_command(template: str) -> str:
    """A rendered remote command that reports missing prerequisites for a
    template, one per line, and exits 0 even when tools are missing."""
    tools = sorted(set(PREREQUISITES["common"]) | set(PREREQUISITES[template]))
    checks = " ".join(f'command -v {tool} >/dev/null 2>&1 || echo "{tool}"' for tool in tools)
    script = f"missing=''; for probe in {tools_needed(tools)}; do :; done\n{checks}; true"
    return remote_command(script, [])


def tools_needed(tools: list[str]) -> str:
    return " ".join(tools)


def parse_missing_tools(stdout: str, exit_code: int | None) -> list[str]:
    if exit_code != 0:
        return ["probe-failed"]
    return [line.strip() for line in stdout.splitlines() if line.strip()]


def template_prerequisite_failure(missing: list[str]) -> str | None:
    """L4: a macOS remote host (or any missing prerequisite) refuses every
    destructive operation before consent; missing tools are displayed per
    template."""
    if missing:
        return f"missing prerequisites: {', '.join(sorted(set(missing)))}"
    return None
