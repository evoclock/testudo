"""Host-side Git bundle/checkpoint verification and publication."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


class PublicationError(ValueError):
    """A bundle, checkpoint, or publication precondition failed."""


_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require_sha(value: object, name: str) -> str:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        raise PublicationError(f"{name} must be a lowercase 40- or 64-character digest")
    return value


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """The tracked checkpoint committed under ``agents/checkpoints``."""

    run_id: str
    task_id: str
    lease_id: str
    repository: str
    branch: str
    base_sha: str
    created_at: str
    completed_subtask: str
    next_action: str
    artifact_refs: tuple[dict[str, str], ...] = ()
    work_head_sha: str | None = None

    SCHEMA = "agent_checkpoint.v1"

    @property
    def path(self) -> str:
        return f"agents/checkpoints/{self.run_id}.json"

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "schema": self.SCHEMA,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "lease_id": self.lease_id,
            "repository": self.repository,
            "branch": self.branch,
            "base_sha": self.base_sha,
            "created_at": self.created_at,
            "completed_subtask": self.completed_subtask,
            "next_action": self.next_action,
            "artifact_refs": [dict(ref) for ref in self.artifact_refs],
        }
        if self.work_head_sha is not None:
            result["work_head_sha"] = self.work_head_sha
        return result

    def bytes(self) -> bytes:
        return (json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")) + "\n").encode()

    @classmethod
    def from_bytes(cls, value: bytes) -> Checkpoint:
        try:
            data = json.loads(value)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PublicationError("checkpoint is not valid JSON") from exc
        if not isinstance(data, dict) or data.get("schema") != cls.SCHEMA:
            raise PublicationError("unsupported checkpoint schema")
        strings = ("run_id", "task_id", "lease_id", "repository", "branch", "base_sha", "created_at", "completed_subtask", "next_action")
        if any(not isinstance(data.get(name), str) or not data[name] for name in strings):
            raise PublicationError("checkpoint identity or progress field is missing")
        if not _ID_RE.fullmatch(data["run_id"]):
            raise PublicationError("checkpoint run_id contains unsafe characters")
        if not data["branch"].startswith("agent/"):
            raise PublicationError("checkpoint must target an agent branch")
        base_sha = _require_sha(data["base_sha"], "base_sha")
        refs = data.get("artifact_refs", [])
        if not isinstance(refs, list) or not all(isinstance(ref, dict) for ref in refs):
            raise PublicationError("artifact_refs must be an object list")
        clean_refs: list[dict[str, str]] = []
        for ref in refs:
            if not all(isinstance(key, str) and isinstance(value, str) for key, value in ref.items()):
                raise PublicationError("artifact references must contain strings")
            digest = ref.get("sha256")
            if digest is not None:
                _require_sha(digest, "artifact sha256")
            clean_refs.append(dict(ref))
        work_head = data.get("work_head_sha")
        if work_head is not None:
            _require_sha(work_head, "work_head_sha")
        return cls(
            run_id=data["run_id"], task_id=data["task_id"], lease_id=data["lease_id"],
            repository=data["repository"], branch=data["branch"], base_sha=base_sha,
            created_at=data["created_at"], completed_subtask=data["completed_subtask"],
            next_action=data["next_action"], artifact_refs=tuple(clean_refs), work_head_sha=work_head,
        )


@dataclass(frozen=True, slots=True)
class PublicationReceipt:
    repository: str
    branch: str
    base_sha: str
    head_sha: str
    checkpoint_sha256: str
    bundle_sha256: str
    scanner_id: str
    policy_hash: str
    remote: str

    SCHEMA = "agent_publication_receipt.v1"

    def to_dict(self) -> dict[str, str]:
        return {
            "schema": self.SCHEMA, "repository": self.repository, "branch": self.branch,
            "base_sha": self.base_sha, "head_sha": self.head_sha,
            "checkpoint_sha256": self.checkpoint_sha256, "bundle_sha256": self.bundle_sha256,
            "scanner_id": self.scanner_id, "policy_hash": self.policy_hash, "remote": self.remote,
        }


class GitBundlePublisher:
    """Import a sanitized bundle and publish only its approved agent branch."""

    def publish(
        self,
        *,
        bundle: Path | str,
        repository: Path | str,
        repository_name: str,
        checkpoint: Checkpoint,
        scan_receipt: dict[str, object],
        remote: str = "origin",
    ) -> PublicationReceipt:
        bundle_path = Path(bundle)
        repo_path = Path(repository)
        if not bundle_path.is_file() or bundle_path.is_symlink():
            raise PublicationError("bundle must be a regular file")
        if not repo_path.is_dir() or not (repo_path / ".git").exists():
            raise PublicationError("repository must be an existing Git checkout")
        if checkpoint.repository != repository_name:
            raise PublicationError("checkpoint repository does not match target")
        if not _ID_RE.fullmatch(remote):
            raise PublicationError("unsafe Git remote name")
        scanner_id = scan_receipt.get("scanner_id")
        policy_hash = scan_receipt.get("policy_hash")
        accepted = scan_receipt.get("accepted")
        expected_bundle_sha = scan_receipt.get("sha256")
        if not accepted or not isinstance(scanner_id, str) or not isinstance(policy_hash, str):
            raise PublicationError("an accepted scanner receipt is required")
        actual_bundle_sha = _digest(bundle_path.read_bytes())
        if expected_bundle_sha != actual_bundle_sha:
            raise PublicationError("bundle does not match scanner receipt")

        self._git(repo_path, "bundle", "verify", str(bundle_path))
        heads = self._git(repo_path, "bundle", "list-heads", str(bundle_path)).stdout.decode()
        head_sha = self._head_for_branch(heads, checkpoint.branch)
        _require_sha(head_sha, "bundle head")
        self._git(repo_path, "cat-file", "-e", f"{checkpoint.base_sha}^{{commit}}")
        quarantine_ref = f"refs/testudo/quarantine/{checkpoint.run_id}"
        self._git(repo_path, "fetch", "--no-tags", str(bundle_path), f"{head_sha}:{quarantine_ref}")
        try:
            if self._git(repo_path, "merge-base", "--is-ancestor", checkpoint.base_sha, quarantine_ref, check=False).returncode != 0:
                raise PublicationError("bundle head is not based on the approved base SHA")

            ref = f"refs/heads/{checkpoint.branch}"
            existing = self._git(repo_path, "rev-parse", "--verify", ref, check=False)
            old_sha = existing.stdout.decode().strip() if existing.returncode == 0 else ""
            if old_sha and self._git(repo_path, "merge-base", "--is-ancestor", old_sha, quarantine_ref, check=False).returncode != 0:
                raise PublicationError("existing agent branch would be rewritten")

            committed_checkpoint = self._git(repo_path, "show", f"{quarantine_ref}:{checkpoint.path}").stdout
            parsed_checkpoint = Checkpoint.from_bytes(committed_checkpoint)
            if parsed_checkpoint.to_dict() != checkpoint.to_dict():
                raise PublicationError("checkpoint in bundle differs from supplied checkpoint")
            self._git(repo_path, "update-ref", ref, quarantine_ref, old_sha)
            self._git(repo_path, "push", remote, f"{ref}:{ref}")
        finally:
            self._git(repo_path, "update-ref", "-d", quarantine_ref, check=False)
        return PublicationReceipt(
            repository=repository_name, branch=checkpoint.branch, base_sha=checkpoint.base_sha,
            head_sha=head_sha, checkpoint_sha256=_digest(committed_checkpoint),
            bundle_sha256=actual_bundle_sha, scanner_id=scanner_id, policy_hash=policy_hash,
            remote=remote,
        )

    @staticmethod
    def _head_for_branch(output: str, branch: str) -> str:
        expected = f"refs/heads/{branch}"
        matches = [line.split()[0] for line in output.splitlines() if len(line.split()) >= 2 and line.split()[1] == expected]
        if len(matches) != 1:
            raise PublicationError("bundle must contain exactly one approved branch head")
        return matches[0]

    @staticmethod
    def _git(cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True)
        if check and result.returncode != 0:
            detail = result.stderr.decode(errors="replace").strip()
            raise PublicationError(f"git {' '.join(args[:2])} failed: {detail}")
        return result


__all__ = ["Checkpoint", "GitBundlePublisher", "PublicationError", "PublicationReceipt"]
