from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from testudo.artifacts import ArtifactStore, EgressRejected


def test_export_scans_each_file_and_deduplicates(tmp_path: Path) -> None:
    source = tmp_path / "exchange"
    source.mkdir()
    (source / "b.txt").write_text("same")
    nested = source / "nested"
    nested.mkdir()
    (nested / "a.txt").write_text("same")
    scanned: list[str] = []

    store = ArtifactStore(tmp_path / "store", store_id="mac-small")
    manifest = store.export_tree(
        source,
        run_id="run-1",
        scanner=lambda path, relative: scanned.append(relative),
        scanner_id="test-scanner",
        policy_hash="policy-test",
    )

    assert scanned == ["b.txt", "nested/a.txt"]
    assert [file.path for file in manifest.files] == scanned
    assert len({file.sha256 for file in manifest.files}) == 1
    digest = hashlib.sha256(b"same").hexdigest()
    assert store.object_path(digest).read_bytes() == b"same"
    written = json.loads((tmp_path / "store/runs/run-1/manifest.json").read_text())
    assert written["schema"] == "artifact_manifest.v1"
    assert written["store_id"] == "mac-small"
    assert written["scanner_id"] == "test-scanner"
    assert written["policy_hash"] == "policy-test"


def test_symlink_is_rejected_before_scanner(tmp_path: Path) -> None:
    source = tmp_path / "exchange"
    source.mkdir()
    target = tmp_path / "outside.txt"
    target.write_text("secret")
    (source / "link.txt").symlink_to(target)
    scanned: list[str] = []

    store = ArtifactStore(tmp_path / "store", store_id="linux-large")
    with pytest.raises(EgressRejected, match="symlink"):
        store.export_tree(
            source,
            run_id="run-2",
            scanner=lambda p, r: scanned.append(r),
            scanner_id="test-scanner",
            policy_hash="policy-test",
        )
    assert scanned == []
    assert not any(path.is_file() for path in (tmp_path / "store/objects").rglob("*"))


def test_scanner_rejection_never_promotes_object(tmp_path: Path) -> None:
    source = tmp_path / "exchange"
    source.mkdir()
    (source / "secret.txt").write_text("token")

    def reject(_path: Path, relative: str) -> None:
        raise ValueError(f"blocked {relative}")

    store = ArtifactStore(tmp_path / "store", store_id="spark-model")
    with pytest.raises(EgressRejected, match="scanner rejected"):
        store.export_tree(
            source,
            run_id="run-3",
            scanner=reject,
            scanner_id="test-scanner",
            policy_hash="policy-test",
        )
    digest = hashlib.sha256(b"token").hexdigest()
    assert not store.object_path(digest).exists()


def test_scanner_mutation_is_detected(tmp_path: Path) -> None:
    source = tmp_path / "exchange"
    source.mkdir()
    (source / "file.txt").write_text("original")

    def mutate(path: Path, _relative: str) -> None:
        path.write_text("changed")

    store = ArtifactStore(tmp_path / "store", store_id="mac-small")
    with pytest.raises(EgressRejected, match="changed during scan"):
        store.export_tree(
            source,
            run_id="run-4",
            scanner=mutate,
            scanner_id="test-scanner",
            policy_hash="policy-test",
        )


def test_quota_rejects_before_cas_promotion(tmp_path: Path) -> None:
    source = tmp_path / "exchange"
    source.mkdir()
    (source / "large.txt").write_text("12345")
    store = ArtifactStore(tmp_path / "store", store_id="mac-small", max_bytes=4)
    with pytest.raises(EgressRejected, match="byte limit"):
        store.export_tree(
            source,
            run_id="run-quota",
            scanner=lambda path, relative: None,
            scanner_id="test-scanner",
            policy_hash="policy-test",
        )
    assert not any(path.is_file() for path in (tmp_path / "store/objects").rglob("*"))
