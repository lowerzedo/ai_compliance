"""Safe creation and atomic finalization of immutable evidence runs."""

from __future__ import annotations

import hashlib
import os
import stat
import threading
import uuid
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, final

from cai_verify.evidence._filesystem import (
    EvidenceResourceLimitError,
    UnsafeEvidencePathError,
    create_anchored_directory,
    open_directory_at,
    scan_regular_files,
)
from cai_verify.evidence.models import (
    MANIFEST_FILENAME,
    MAX_ARTIFACT_BYTES,
    MAX_MANIFEST_BYTES,
    MAX_RUN_ARTIFACT_BYTES,
    ManifestArtifact,
    RunManifest,
    Sensitivity,
    validate_artifact_path,
    validate_media_type,
    validate_run_id,
)
from cai_verify.plugins.contracts import FinalizedManifest

if TYPE_CHECKING:
    from types import TracebackType

_STAGING_DIRECTORY = ".cai-staging"
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_CREATE_FILE_FLAGS = os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC
_READ_FILE_FLAGS = os.O_RDONLY | _NOFOLLOW | _CLOEXEC


class EvidenceRunError(RuntimeError):
    """Base class for safe evidence-run lifecycle failures."""


class RunAlreadyExistsError(EvidenceRunError):
    """Raised when exclusive run creation finds an existing entry."""


class RunFinalizedError(EvidenceRunError):
    """Raised when a caller tries to mutate or re-finalize a run."""


class EvidenceAlreadyExistsError(EvidenceRunError):
    """Raised when an artifact path would overwrite an existing entry."""


class IncompleteRunError(EvidenceRunError):
    """Raised when interrupted, untracked, missing, or changed files are found."""


class ClosedRunError(EvidenceRunError):
    """Raised when an operation uses a closed run handle."""


@dataclass(frozen=True, slots=True)
class _PublicationExpectation:
    digest: str
    size: int
    link_count: int


@final
class RunDirectory:
    """Descriptor-anchored writer for one exclusively created evidence run."""

    def __init__(
        self,
        *,
        path: Path,
        run_id: str,
        root_fd: int,
        run_fd: int,
    ) -> None:
        """Initialize a handle created through :meth:`create`."""
        self._path = path
        self._run_id = run_id
        self._root_fd = root_fd
        self._run_fd = run_fd
        self._artifacts: dict[str, ManifestArtifact] = {}
        self._closed = False
        self._finalized = False
        self._lock = threading.RLock()

    @classmethod
    def create(cls, runs_root: str | os.PathLike[str], run_id: str) -> RunDirectory:
        """Exclusively create a private run directory beneath a safe root."""
        validated_run_id = validate_run_id(run_id)
        root = Path(
            os.path.abspath(  # noqa: PTH100 - must not follow untrusted symlinks
                os.fspath(runs_root)
            )
        )
        root_fd = create_anchored_directory(root)
        run_created = False
        run_fd: int | None = None
        try:
            try:
                os.mkdir(validated_run_id, mode=0o700, dir_fd=root_fd)
                run_created = True
            except FileExistsError as exc:
                message = "run directory already exists"
                raise RunAlreadyExistsError(message) from exc
            run_fd = open_directory_at(
                root_fd,
                validated_run_id,
                display_path=validated_run_id,
            )
            os.mkdir(_STAGING_DIRECTORY, mode=0o700, dir_fd=run_fd)
            os.fsync(run_fd)
            os.fsync(root_fd)
            return cls(
                path=root / validated_run_id,
                run_id=validated_run_id,
                root_fd=root_fd,
                run_fd=run_fd,
            )
        except Exception:
            if run_fd is not None:
                with suppress(OSError):
                    os.rmdir(_STAGING_DIRECTORY, dir_fd=run_fd)
                os.close(run_fd)
            if run_created:
                with suppress(OSError):
                    os.rmdir(validated_run_id, dir_fd=root_fd)
            os.close(root_fd)
            raise

    @property
    def path(self) -> Path:
        """Return the caller-visible absolute run path."""
        return self._path

    @property
    def run_id(self) -> str:
        """Return the validated run identifier."""
        return self._run_id

    @property
    def finalized(self) -> bool:
        """Return whether this handle has successfully finalized its manifest."""
        return self._finalized

    def write_evidence(
        self,
        relative_path: str,
        content: bytes,
        *,
        media_type: str,
        sensitivity: Sensitivity,
    ) -> ManifestArtifact:
        """Atomically create one artifact without exposing partial target bytes."""
        components = validate_artifact_path(relative_path)
        validate_media_type(media_type)
        if not isinstance(content, bytes):
            message = "content must be bytes"
            raise TypeError(message)
        if len(content) > MAX_ARTIFACT_BYTES:
            message = "content exceeds the maximum artifact size"
            raise ValueError(message)
        if not isinstance(sensitivity, Sensitivity):
            message = "sensitivity must be a Sensitivity"
            raise TypeError(message)

        with self._lock:
            self._ensure_mutable()
            if (
                sum(item.size_bytes for item in self._artifacts.values()) + len(content)
                > MAX_RUN_ARTIFACT_BYTES
            ):
                message = "content exceeds the maximum run artifact size"
                raise ValueError(message)
            stored_digest, stored_size = self._publish_evidence_bytes(
                components,
                content,
            )

            artifact = ManifestArtifact(
                path=relative_path,
                media_type=media_type,
                sensitivity=sensitivity,
                sha256=stored_digest,
                size_bytes=stored_size,
            )
            self._artifacts[relative_path] = artifact
            return artifact

    def _publish_evidence_bytes(
        self,
        components: tuple[str, ...],
        content: bytes,
    ) -> tuple[str, int]:
        parent_fd = self._open_or_create_parent(components[:-1])
        temporary_name = f"artifact-{uuid.uuid4().hex}.partial"
        staging_fd: int | None = None
        temporary_fd: int | None = None
        linked = False
        try:
            staging_fd = self._open_staging()
            temporary_fd = os.open(
                temporary_name,
                _CREATE_FILE_FLAGS,
                0o600,
                dir_fd=staging_fd,
            )
            _write_all(temporary_fd, content)
            os.fsync(temporary_fd)
            stored_digest, stored_size = _hash_descriptor(temporary_fd)
            os.link(
                temporary_name,
                components[-1],
                src_dir_fd=staging_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
            linked = True
            _verify_published_file(
                temporary_fd,
                parent_fd,
                components[-1],
                _PublicationExpectation(stored_digest, stored_size, 2),
            )
            os.unlink(temporary_name, dir_fd=staging_fd)
            _verify_published_file(
                temporary_fd,
                parent_fd,
                components[-1],
                _PublicationExpectation(stored_digest, stored_size, 1),
            )
            os.fsync(parent_fd)
            os.fsync(staging_fd)
        except FileExistsError as exc:
            if linked:
                _unlink_if_present(parent_fd, components[-1])
            message = "evidence artifact already exists"
            raise EvidenceAlreadyExistsError(message) from exc
        except Exception:
            if linked:
                _unlink_if_present(parent_fd, components[-1])
            raise
        finally:
            if temporary_fd is not None:
                os.close(temporary_fd)
            if staging_fd is not None:
                _unlink_if_present(staging_fd, temporary_name)
                os.close(staging_fd)
            os.close(parent_fd)
        return stored_digest, stored_size

    def finalize_manifest(self) -> FinalizedManifest:
        """Verify all stored bytes, then atomically create the manifest last."""
        with self._lock:
            self._ensure_mutable()
            self._remove_empty_staging_directory()
            try:
                scanned = scan_regular_files(
                    self._run_fd,
                    exclude_root_manifest=False,
                )
            except EvidenceResourceLimitError as exc:
                message = "run exceeds evidence finalization resource limits"
                raise IncompleteRunError(message) from exc
            if set(scanned) != set(self._artifacts):
                message = "run contains missing or untracked artifacts"
                raise IncompleteRunError(message)

            finalized_artifacts: list[ManifestArtifact] = []
            for path, recorded in self._artifacts.items():
                stored = scanned[path]
                if (
                    stored.sha256 != recorded.sha256
                    or stored.size_bytes != recorded.size_bytes
                ):
                    message = "an evidence artifact changed before finalization"
                    raise IncompleteRunError(message)
                finalized_artifacts.append(
                    ManifestArtifact(
                        path=path,
                        media_type=recorded.media_type,
                        sensitivity=recorded.sensitivity,
                        sha256=stored.sha256,
                        size_bytes=stored.size_bytes,
                    )
                )

            manifest = RunManifest(
                run_id=self._run_id,
                artifacts=tuple(finalized_artifacts),
            )
            manifest_bytes = manifest.to_bytes()
            if len(manifest_bytes) > MAX_MANIFEST_BYTES:
                message = "manifest exceeds the maximum supported size"
                raise IncompleteRunError(message)
            self._write_manifest_last(manifest_bytes)
            self._finalized = True
            return FinalizedManifest(manifest_bytes)

    def close(self) -> None:
        """Close pinned directory descriptors without changing run contents."""
        with self._lock:
            if self._closed:
                return
            os.close(self._run_fd)
            os.close(self._root_fd)
            self._closed = True

    def __enter__(self) -> RunDirectory:
        """Return this open run handle."""
        self._ensure_open()
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close descriptors when leaving a context manager."""
        del exception_type, exception, traceback
        self.close()

    def _ensure_open(self) -> None:
        if self._closed:
            message = "run directory handle is closed"
            raise ClosedRunError(message)

    def _ensure_mutable(self) -> None:
        self._ensure_open()
        self._assert_anchor_unchanged()
        if self._finalized or _entry_exists(self._run_fd, MANIFEST_FILENAME):
            message = "finalized runs cannot be modified"
            raise RunFinalizedError(message)

    def _assert_anchor_unchanged(self) -> None:
        current = os.fstat(self._run_fd)
        try:
            anchored = os.stat(
                self._run_id,
                dir_fd=self._root_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise UnsafeEvidencePathError(self._run_id) from exc
        if (
            stat.S_ISLNK(anchored.st_mode)
            or not stat.S_ISDIR(anchored.st_mode)
            or (anchored.st_dev, anchored.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise UnsafeEvidencePathError(self._run_id)

    def _open_or_create_parent(self, components: tuple[str, ...]) -> int:
        current_fd = os.dup(self._run_fd)
        traversed: list[str] = []
        try:
            for component in components:
                traversed.append(component)
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current_fd)
                    os.fsync(current_fd)
                except FileExistsError:
                    pass
                child_fd = open_directory_at(
                    current_fd,
                    component,
                    display_path="/".join(traversed),
                )
                os.close(current_fd)
                current_fd = child_fd
        except Exception:
            os.close(current_fd)
            raise
        else:
            return current_fd

    def _open_staging(self) -> int:
        try:
            return open_directory_at(
                self._run_fd,
                _STAGING_DIRECTORY,
                display_path=_STAGING_DIRECTORY,
            )
        except UnsafeEvidencePathError:
            if _entry_exists(self._run_fd, _STAGING_DIRECTORY):
                raise
            os.mkdir(_STAGING_DIRECTORY, mode=0o700, dir_fd=self._run_fd)
            os.fsync(self._run_fd)
            return open_directory_at(
                self._run_fd,
                _STAGING_DIRECTORY,
                display_path=_STAGING_DIRECTORY,
            )

    def _remove_empty_staging_directory(self) -> None:
        staging_fd = self._open_staging()
        try:
            with os.scandir(staging_fd) as entries:
                if next(entries, None) is not None:
                    message = "run contains an interrupted evidence write"
                    raise IncompleteRunError(message)
        finally:
            os.close(staging_fd)
        os.rmdir(_STAGING_DIRECTORY, dir_fd=self._run_fd)
        os.fsync(self._run_fd)

    def _write_manifest_last(self, content: bytes) -> None:
        temporary_name = f".cai-manifest-{self._run_id}-{uuid.uuid4().hex}.partial"
        temporary_fd: int | None = None
        linked = False
        published = False
        try:
            temporary_fd = os.open(
                temporary_name,
                _CREATE_FILE_FLAGS,
                0o600,
                dir_fd=self._root_fd,
            )
            _write_all(temporary_fd, content)
            os.fsync(temporary_fd)
            digest, size = _hash_descriptor(temporary_fd)
            _require_expected_staging_bytes(content, digest=digest, size=size)
            os.link(
                temporary_name,
                MANIFEST_FILENAME,
                src_dir_fd=self._root_fd,
                dst_dir_fd=self._run_fd,
                follow_symlinks=False,
            )
            linked = True
            _verify_published_file(
                temporary_fd,
                self._run_fd,
                MANIFEST_FILENAME,
                _PublicationExpectation(digest, size, 2),
            )
            os.unlink(temporary_name, dir_fd=self._root_fd)
            _verify_published_file(
                temporary_fd,
                self._run_fd,
                MANIFEST_FILENAME,
                _PublicationExpectation(digest, size, 1),
            )
            os.fsync(self._run_fd)
            os.fsync(self._root_fd)
            published = True
        except FileExistsError as exc:
            message = "finalized runs cannot be overwritten"
            raise RunFinalizedError(message) from exc
        except Exception:
            if linked and not published:
                _unlink_if_present(self._run_fd, MANIFEST_FILENAME)
            raise
        finally:
            if temporary_fd is not None:
                os.close(temporary_fd)
            _unlink_if_present(self._root_fd, temporary_name)


def create_run_directory(
    runs_root: str | os.PathLike[str],
    run_id: str,
) -> RunDirectory:
    """Create and return one exclusive descriptor-anchored run writer."""
    return RunDirectory.create(runs_root, run_id)


def _write_all(descriptor: int, content: bytes) -> None:
    remaining = memoryview(content)
    while remaining:
        try:
            written = os.write(descriptor, remaining)
        except InterruptedError:
            continue
        if written <= 0:
            message = "atomic evidence write made no progress"
            raise OSError(message)
        remaining = remaining[written:]


def _hash_descriptor(descriptor: int) -> tuple[str, int]:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    size = 0
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def _require_expected_staging_bytes(
    content: bytes,
    *,
    digest: str,
    size: int,
) -> None:
    if digest != hashlib.sha256(content).hexdigest() or size != len(content):
        message = "manifest staging bytes changed unexpectedly"
        raise EvidenceRunError(message)


def _verify_published_file(
    source_fd: int,
    destination_parent_fd: int,
    destination_name: str,
    expectation: _PublicationExpectation,
) -> None:
    """Bind a published name to the exact opened and hashed staging inode."""
    source_metadata = os.fstat(source_fd)
    try:
        destination_fd = os.open(
            destination_name,
            _READ_FILE_FLAGS,
            dir_fd=destination_parent_fd,
        )
    except OSError as exc:
        raise UnsafeEvidencePathError(destination_name) from exc
    try:
        before = os.fstat(destination_fd)
        if (
            not stat.S_ISREG(source_metadata.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or source_metadata.st_nlink != expectation.link_count
            or before.st_nlink != expectation.link_count
            or (source_metadata.st_dev, source_metadata.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            raise UnsafeEvidencePathError(destination_name)
        digest, size = _hash_descriptor(destination_fd)
        after = os.fstat(destination_fd)
        if (
            (
                before.st_dev,
                before.st_ino,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
            )
            or digest != expectation.digest
            or size != expectation.size
        ):
            message = "published bytes do not match the staged evidence"
            raise EvidenceRunError(message)
    finally:
        os.close(destination_fd)


def _entry_exists(directory_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _unlink_if_present(directory_fd: int, name: str) -> None:
    with suppress(FileNotFoundError):
        os.unlink(name, dir_fd=directory_fd)
