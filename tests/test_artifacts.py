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


def _store_with_object(tmp_path: Path, payload: bytes) -> tuple[ArtifactStore, str]:
    store = ArtifactStore(tmp_path / "store", store_id="store-1")
    source = tmp_path / "src"
    source.mkdir()
    (source / "out.txt").write_bytes(payload)
    manifest = store.export_tree(
        source,
        run_id="run-1",
        scanner=lambda path, rel: None,
        scanner_id="scanner-1",
        policy_hash="p" * 64,
    )
    return store, manifest.files[0].sha256


def test_materialize_writes_verified_bytes_into_destination(tmp_path: Path) -> None:
    payload = b"clean scanned output\n"
    store, sha256 = _store_with_object(tmp_path, payload)
    destination = tmp_path / "land"
    destination.mkdir()
    written = store.materialize([{"name": "patch/out.txt", "sha256": sha256}], destination)
    assert written == [destination / "patch" / "out.txt"]
    assert (destination / "patch" / "out.txt").read_bytes() == payload


def test_materialize_refuses_digest_mismatch(tmp_path: Path) -> None:
    store, sha256 = _store_with_object(tmp_path, b"payload")
    destination = tmp_path / "land"
    destination.mkdir()
    bad = "0" * 64 if sha256[0] != "0" else "1" * 64
    with pytest.raises(EgressRejected, match="not in the store"):
        store.materialize([{"name": "x.txt", "sha256": bad}], destination)


def test_materialize_refuses_traversal_and_absolute_names(tmp_path: Path) -> None:
    store, sha256 = _store_with_object(tmp_path, b"payload")
    destination = tmp_path / "land"
    destination.mkdir()
    for name in ("../escape.txt", "/etc/passwd", "a/../../b"):
        with pytest.raises(EgressRejected, match="escapes the destination"):
            store.materialize([{"name": name, "sha256": sha256}], destination)
    # A doubled slash normalizes away; the write still lands inside and is allowed.
    written = store.materialize([{"name": "a//b", "sha256": sha256}], destination)
    assert written == [destination / "a" / "b"]


def test_materialize_refuses_existing_destination(tmp_path: Path) -> None:
    store, sha256 = _store_with_object(tmp_path, b"payload")
    destination = tmp_path / "land"
    destination.mkdir()
    (destination / "out.txt").write_bytes(b"occupied")
    with pytest.raises(EgressRejected, match="already exists"):
        store.materialize([{"name": "out.txt", "sha256": sha256}], destination)


def test_materialize_refuses_invalid_digest_shape(tmp_path: Path) -> None:
    store, _sha256 = _store_with_object(tmp_path, b"payload")
    destination = tmp_path / "land"
    destination.mkdir()
    with pytest.raises(EgressRejected, match="valid SHA-256"):
        store.materialize([{"name": "x", "sha256": "ZZ" * 32}], destination)
