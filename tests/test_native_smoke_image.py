# SPDX-FileCopyrightText: 2026 Julen Gamboa <[REDACTED:email_address]>
# SPDX-License-Identifier: AGPL-3.0-only

"""Static contract tests for the Apple native-container smoke image.

The native-smoke image is a build recipe for Apple's native container runtime
only - never a Docker runtime fallback. It must carry the full in-image guest
supervisor chain (supervisor, monitor, taxonomy, bootstrap) because the
native-container adapter requires the supervisor as the entry command and the
supervisor verifies the taxonomy digest before any guest work starts. The
recipe is stdlib-only: no package manager or install command may appear.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile.native-smoke"
SUPERVISOR = ROOT / "guest" / "testudo_contained_guest.sh"
MONITOR = ROOT / "guest" / "testudo_containment_monitor.sh"
TAXONOMY = ROOT / "src" / "testudo" / "runtime" / "guest_containment_taxonomy.v1.json"
BOOTSTRAP = ROOT / "guest" / "testudo_guest_bootstrap.py"


def test_native_smoke_image_installs_the_full_guest_supervisor_chain() -> None:
    recipe = DOCKERFILE.read_text(encoding="utf-8")
    # Every required guest component is COPYed from its repository path.
    for component in (
        "guest/testudo_contained_guest.sh",
        "guest/testudo_containment_monitor.sh",
        "src/testudo/runtime/guest_containment_taxonomy.v1.json",
        "guest/testudo_guest_bootstrap.py",
    ):
        assert f"COPY {component} " in recipe, f"missing COPY for {component}"
    # The supervisor entrypoint matches the adapter's required entry command.
    entry = [line for line in recipe.splitlines() if line.startswith("ENTRYPOINT")]
    assert entry, "the smoke image must declare its entrypoint"
    assert "/opt/testudo/testudo_contained_guest.sh" in entry[0]
    # The supervisor's default paths must match the installed locations.
    supervisor = SUPERVISOR.read_text(encoding="utf-8")
    assert "TESTUDO_CONTAINMENT_MONITOR:-/opt/testudo/testudo_containment_monitor.sh" in supervisor
    assert "TESTUDO_GUEST_BOOTSTRAP:-/opt/testudo/testudo_guest_bootstrap.py" in supervisor
    assert (
        "TESTUDO_CONTAINMENT_TAXONOMY:-/opt/testudo/guest_containment_taxonomy.v1.json"
        in supervisor
    )
    # The recipe exposes no Docker-runtime fallback surface.
    assert "docker.io/library/python" in recipe


def test_native_smoke_image_is_stdlib_only_with_no_install_step() -> None:
    recipe = DOCKERFILE.read_text(encoding="utf-8")
    lowered = recipe.lower()
    for forbidden in ("apt-get", "apk add", "pip install", "uv ", "npm ", "curl ", "wget "):
        assert forbidden not in lowered, f"install/fetch step forbidden in smoke image: {forbidden}"
    # The base image is pinned by digest, not a floating tag.
    assert "@sha256:" in recipe


def test_native_smoke_guest_chain_is_present_and_coherent() -> None:
    # The supervisor sources the monitor and verifies the taxonomy digest.
    supervisor = SUPERVISOR.read_text(encoding="utf-8")
    assert '. "$MONITOR"' in supervisor
    assert "actual_taxonomy_sha" in supervisor
    assert "GC_TAXONOMY_SHA256" in supervisor
    # The monitor owns the canonical taxonomy byte-for-byte.
    monitor = MONITOR.read_text(encoding="utf-8")
    assert "GC_TAXONOMY_EOF" in monitor
    # The bootstrap is the workflow-capable guest entrypoint the supervisor
    # launches, and it reads the contract's declared workspace path.
    bootstrap = BOOTSTRAP.read_text(encoding="utf-8")
    assert "_bind_writable_paths" in bootstrap
    assert "TESTUDO_GUEST_WORKSPACE" in bootstrap
    # The taxonomy file the recipe installs is the canonical JSON.
    import json

    taxonomy = json.loads(TAXONOMY.read_text(encoding="utf-8"))
    assert taxonomy["schema"] == "guest-containment-taxonomy.v1"
