from __future__ import annotations

import hashlib
import json
import subprocess

import pytest

from testudo.runtime.publisher import Checkpoint, GitBundlePublisher, PublicationError


def git(cwd, *args, check=True):
    result = subprocess.run(["git", "-C", str(cwd), *args], text=True, capture_output=True)
    if check:
        assert result.returncode == 0, result.stderr
    return result


def make_source(tmp_path):
    source = tmp_path / "source"
    remote = tmp_path / "remote.git"
    target = tmp_path / "testudo-agents"
    source.mkdir()
    git(source, "init", "-b", "main")
    git(source, "config", "user.email", "test@example.invalid")
    git(source, "config", "user.name", "Test Publisher")
    (source / "README.md").write_text("base\n")
    git(source, "add", "README.md")
    git(source, "commit", "-m", "base")
    base_sha = git(source, "rev-parse", "HEAD").stdout.strip()
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    git(source, "remote", "add", "origin", str(remote))
    git(source, "push", "origin", "main")
    subprocess.run(["git", "clone", str(remote), str(target)], check=True, capture_output=True)
    git(target, "config", "user.email", "test@example.invalid")
    git(target, "config", "user.name", "Test Publisher")

    branch = "agent/T-0254/run-1"
    git(source, "checkout", "-b", branch)
    checkpoint = Checkpoint(
        run_id="run-1", task_id="T-0254", lease_id="lease-1", repository="testudo-agents",
        branch=branch, base_sha=base_sha, created_at="2026-08-08T12:00:00Z",
        completed_subtask="publisher", next_action="review", artifact_refs=(),
    )
    checkpoint_path = source / checkpoint.path
    checkpoint_path.parent.mkdir(parents=True)
    checkpoint_path.write_bytes(checkpoint.bytes())
    (source / "change.txt").write_text("contained change\n")
    git(source, "add", ".")
    git(source, "commit", "-m", "checkpoint")
    bundle = tmp_path / "run-1.bundle"
    git(source, "bundle", "create", str(bundle), f"refs/heads/{branch}")
    return target, remote, bundle, checkpoint


def test_publisher_verifies_imports_and_pushes_agent_branch(tmp_path):
    target, remote, bundle, checkpoint = make_source(tmp_path)
    bundle_sha = hashlib.sha256(bundle.read_bytes()).hexdigest()
    receipt = {
        "accepted": True, "sha256": bundle_sha, "scanner_id": "host-egress-v1", "policy_hash": "b" * 64,
    }
    publication = GitBundlePublisher().publish(
        bundle=bundle, repository=target, repository_name="testudo-agents",
        checkpoint=checkpoint, scan_receipt=receipt,
    )
    assert publication.branch == checkpoint.branch
    assert publication.head_sha
    assert publication.bundle_sha256 == bundle_sha
    assert git(target, "show", f"{publication.head_sha}:{checkpoint.path}").returncode == 0
    assert git(target, "ls-remote", str(remote), f"refs/heads/{checkpoint.branch}").returncode == 0


def test_publisher_rejects_unscanned_or_tampered_bundle(tmp_path):
    target, _remote, bundle, checkpoint = make_source(tmp_path)
    with pytest.raises(PublicationError, match="scanner receipt"):
        GitBundlePublisher().publish(
            bundle=bundle, repository=target, repository_name="testudo-agents",
            checkpoint=checkpoint, scan_receipt={"accepted": False},
        )
    receipt = {"accepted": True, "sha256": "0" * 64, "scanner_id": "scan", "policy_hash": "b" * 64}
    with pytest.raises(PublicationError, match="does not match"):
        GitBundlePublisher().publish(
            bundle=bundle, repository=target, repository_name="testudo-agents",
            checkpoint=checkpoint, scan_receipt=receipt,
        )


def test_checkpoint_rejects_unsafe_branch_and_invalid_digest():
    data = {
        "schema": "agent_checkpoint.v1", "run_id": "run-1", "task_id": "T-0254", "lease_id": "lease-1",
        "repository": "testudo-agents", "branch": "main", "base_sha": "a" * 40,
        "created_at": "now", "completed_subtask": "x", "next_action": "y", "artifact_refs": [],
    }
    with pytest.raises(PublicationError, match="agent branch"):
        Checkpoint.from_bytes((json.dumps(data)).encode())
