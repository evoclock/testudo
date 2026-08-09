"""Host-local, content-addressed storage for container egress.

The container must write only to a controller-created exchange directory.  The
controller calls :meth:`ArtifactStore.export_tree`; this is the only path that
promotes bytes into the final store.  Each regular file is copied to quarantine,
scanned, re-hashed, and atomically renamed to its SHA-256 object path.  Symlinks
and special files are rejected rather than followed.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
from collections.abc import Callable, Iterator
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

ChunkScanner = Callable[[Path, str], None]


class EgressRejected(RuntimeError):
    """Raised when a container output cannot be safely promoted."""


@dataclass(frozen=True, slots=True)
class ExportedFile:
    """Receipt for one file crossing the container egress boundary."""

    path: str
    size_bytes: int
    sha256: str
    operations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExportManifest:
    """Manifest written after all files in an export have been accepted."""

    schema: str
    store_id: str
    run_id: str
    scanner_id: str
    policy_hash: str
    files: tuple[ExportedFile, ...]
    total_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "store_id": self.store_id,
            "run_id": self.run_id,
            "scanner_id": self.scanner_id,
            "policy_hash": self.policy_hash,
            "files": [asdict(file) for file in self.files],
            "total_bytes": self.total_bytes,
        }


class ArtifactStore:
    """Simple filesystem CAS owned by one worker host.

    ``root`` is local disk and is never mounted into the container.  The source
    exchange is read by this host-side importer and the object tree is written
    only after the configured scanner accepts the file.
    """

    def __init__(
        self,
        root: Path | str,
        *,
        store_id: str,
        max_files: int | None = None,
        max_bytes: int | None = None,
    ) -> None:
        if not store_id or "/" in store_id or "\\" in store_id:
            raise ValueError("store_id must be a non-empty path component")
        self.root = Path(root).expanduser().resolve()
        self.store_id = store_id
        self.max_files = max_files
        self.max_bytes = max_bytes
        self.objects_root = self.root / "objects" / "sha256"
        self.quarantine_root = self.root / "quarantine"
        self.runs_root = self.root / "runs"
        for directory in (self.objects_root, self.quarantine_root, self.runs_root):
            directory.mkdir(parents=True, exist_ok=True)

    def export_tree(
        self,
        source_root: Path | str,
        *,
        run_id: str,
        scanner: ChunkScanner,
        scanner_id: str,
        policy_hash: str,
    ) -> ExportManifest:
        """Scan and promote every regular file in ``source_root``.

        The scanner receives a quarantined path and its relative POSIX path for
        every file.  A scanner exception fails the whole export.  A second hash
        after scanning detects a scanner or concurrent writer changing bytes.
        """
        if not run_id or "/" in run_id or "\\" in run_id:
            raise ValueError("run_id must be a non-empty path component")
        if not scanner_id or not policy_hash:
            raise ValueError("scanner_id and policy_hash are required")
        source = Path(source_root).resolve()
        if not source.is_dir():
            raise EgressRejected(f"output exchange is not a directory: {source}")

        quarantine = self.quarantine_root / run_id
        quarantine.mkdir(parents=True, exist_ok=False)
        exported: list[ExportedFile] = []
        total_bytes = 0
        for source_path, relative in _walk_regular_files(source):
            if self.max_files is not None and len(exported) >= self.max_files:
                raise EgressRejected("output file limit exceeded")
            if self.max_bytes is not None:
                source_size = _regular_lstat(source_path).st_size
                if total_bytes + source_size > self.max_bytes:
                    raise EgressRejected("output byte limit exceeded")
            entry = self._export_one(
                source_path,
                relative=relative,
                quarantine=quarantine,
                scanner=scanner,
            )
            exported.append(entry)
            total_bytes += entry.size_bytes

        manifest = ExportManifest(
            schema="artifact_manifest.v1",
            store_id=self.store_id,
            run_id=run_id,
            scanner_id=scanner_id,
            policy_hash=policy_hash,
            files=tuple(exported),
            total_bytes=total_bytes,
        )
        manifest_path = self.runs_root / run_id / "manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=False)
        _atomic_json_write(manifest_path, manifest.to_dict())
        return manifest

    def object_path(self, sha256: str) -> Path:
        """Return the deterministic object path for a digest."""
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise ValueError("sha256 must be a lowercase 64-character hex digest")
        return self.objects_root / sha256[:2] / sha256[2:4] / sha256

    def _export_one(
        self,
        source_path: Path,
        *,
        relative: PurePosixPath,
        quarantine: Path,
        scanner: ChunkScanner,
    ) -> ExportedFile:
        operations = ["source.lstat", "source.read", "quarantine.write"]
        before = _regular_lstat(source_path)
        quarantine_path = quarantine.joinpath(*relative.parts)
        quarantine_path.parent.mkdir(parents=True, exist_ok=True)
        digest, size = _copy_regular(source_path, quarantine_path, before)
        after = _regular_lstat(source_path)
        if _stat_fingerprint(before) != _stat_fingerprint(after):
            raise EgressRejected(f"source changed during export: {relative}")

        operations.append("quarantine.scan")
        try:
            scanner(quarantine_path, relative.as_posix())
        except Exception as exc:
            raise EgressRejected(f"scanner rejected {relative}: {exc}") from exc

        operations.append("quarantine.rehash")
        final_digest, final_size = _hash_regular(quarantine_path)
        if final_digest != digest or final_size != size:
            raise EgressRejected(f"quarantined file changed during scan: {relative}")

        object_path = self.object_path(final_digest)
        object_path.parent.mkdir(parents=True, exist_ok=True)
        operations.append("cas.commit")
        if object_path.exists():
            existing_digest, existing_size = _hash_regular(object_path)
            if existing_digest != final_digest or existing_size != final_size:
                raise EgressRejected(f"CAS collision or corruption: {final_digest}")
            quarantine_path.unlink()
        else:
            os.replace(quarantine_path, object_path)
            _fsync_directory(object_path.parent)
        return ExportedFile(
            path=relative.as_posix(),
            size_bytes=final_size,
            sha256=final_digest,
            operations=tuple(operations),
        )


def _walk_regular_files(root: Path) -> Iterator[tuple[Path, PurePosixPath]]:
    """Yield sorted regular files and reject links/special files."""

    def walk(directory: Path, relative: PurePosixPath) -> Iterator[tuple[Path, PurePosixPath]]:
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            raise EgressRejected(f"cannot enumerate output exchange: {directory}: {exc}") from exc
        for entry in entries:
            child_relative = relative / entry.name
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise EgressRejected(f"cannot inspect output path {child_relative}: {exc}") from exc
            if stat.S_ISLNK(info.st_mode):
                raise EgressRejected(f"symlink in output exchange: {child_relative}")
            child = Path(entry.path)
            if stat.S_ISDIR(info.st_mode):
                yield from walk(child, child_relative)
            elif stat.S_ISREG(info.st_mode):
                yield child, child_relative
            else:
                raise EgressRejected(f"special file in output exchange: {child_relative}")

    yield from walk(root, PurePosixPath())


def _regular_lstat(path: Path) -> os.stat_result:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise EgressRejected(f"not a regular file: {path}")
    return info


def _stat_fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_mode)


def _copy_regular(path: Path, destination: Path, expected: os.stat_result) -> tuple[str, int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise EgressRejected("platform lacks O_NOFOLLOW; refusing unguarded export")
    flags |= nofollow
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise EgressRejected(f"cannot open output file {path}: {exc}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or _stat_fingerprint(opened) != _stat_fingerprint(
            expected
        ):
            raise EgressRejected(f"output file changed before read: {path}")
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(fd, "rb", closefd=True) as source, destination.open("xb") as target:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        return digest.hexdigest(), size
    except Exception:
        with suppress(OSError):
            os.close(fd)
        destination.unlink(missing_ok=True)
        raise


def _hash_regular(path: Path) -> tuple[str, int]:
    _regular_lstat(path)
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _atomic_json_write(path: Path, value: dict[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _fsync_directory(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


__all__ = ["ArtifactStore", "ChunkScanner", "EgressRejected", "ExportManifest", "ExportedFile"]
