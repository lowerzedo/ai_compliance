"""Descriptor-relative filesystem primitives for evidence bundles."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cai_verify.evidence.models import (
    MANIFEST_FILENAME,
    MAX_ARTIFACT_BYTES,
    MAX_ARTIFACT_PATH_COMPONENTS,
    MAX_ARTIFACT_PATH_LENGTH,
    MAX_RUN_ARTIFACT_BYTES,
    MAX_SCAN_ENTRIES,
)

if TYPE_CHECKING:
    from pathlib import Path

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_DIRECTORY_FLAGS = os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC
_READ_FLAGS = os.O_RDONLY | _NOFOLLOW | _CLOEXEC


class UnsafeEvidencePathError(ValueError):
    """Raised when a path is a symlink, special file, or escapes its anchor."""

    def __init__(self, path: str | None = None) -> None:
        """Identify only the run-relative unsafe path, never file content."""
        self.path = path
        message = "evidence path is unsafe"
        if path is not None:
            message = f"evidence path is unsafe: {path}"
        super().__init__(message)


class UnstableEvidenceFileError(OSError):
    """Raised when file metadata changes while its bytes are being hashed."""

    def __init__(self, path: str) -> None:
        """Record the affected run-relative path."""
        self.path = path
        super().__init__("evidence file changed while it was being read")


class EvidenceResourceLimitError(OSError):
    """Raised when an untrusted evidence tree exceeds verification budgets."""

    def __init__(self, path: str | None = None) -> None:
        """Record only the run-relative entry at which the budget was exceeded."""
        self.path = path
        super().__init__("evidence tree exceeds a verification resource limit")


@dataclass(frozen=True, slots=True)
class ScannedFile:
    """Digest and size read from one exact regular file."""

    sha256: str
    size_bytes: int


@dataclass(slots=True)
class _ScanBudget:
    entries: int = 0
    artifact_bytes: int = 0


@dataclass(slots=True)
class _ScanContext:
    exclude_root_manifest: bool
    result: dict[str, ScannedFile]
    budget: _ScanBudget


def open_anchored_directory(path: Path) -> int:
    """Open an existing absolute path without following any symlink component."""
    return _walk_anchored_directory(path, create=False)


def create_anchored_directory(path: Path) -> int:
    """Create missing path components without following any existing symlink."""
    return _walk_anchored_directory(path, create=True)


def _walk_anchored_directory(path: Path, *, create: bool) -> int:
    if _NOFOLLOW == 0 or _DIRECTORY == 0:
        message = "secure evidence storage requires O_NOFOLLOW and O_DIRECTORY"
        raise NotImplementedError(message)
    if not path.is_absolute() or ".." in path.parts:
        raise UnsafeEvidencePathError
    try:
        current_fd = os.open("/", _DIRECTORY_FLAGS)
    except OSError as exc:
        raise UnsafeEvidencePathError from exc
    traversed: list[str] = []
    try:
        for component in path.parts[1:]:
            traversed.append(component)
            display_path = "/".join(traversed)
            if create:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current_fd)
                    os.fsync(current_fd)
                except FileExistsError:
                    pass
            child_fd = open_directory_at(
                current_fd,
                component,
                display_path=display_path,
            )
            os.close(current_fd)
            current_fd = child_fd
    except Exception:
        os.close(current_fd)
        raise
    return current_fd


def open_directory_at(parent_fd: int, name: str, *, display_path: str) -> int:
    """Open one directory component without following a symlink."""
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise UnsafeEvidencePathError(display_path) from exc
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise UnsafeEvidencePathError(display_path)
    return descriptor


def hash_file_at(
    parent_fd: int,
    name: str,
    *,
    display_path: str,
    maximum_bytes: int = MAX_ARTIFACT_BYTES,
) -> ScannedFile:
    """Hash the exact bytes of a stable, non-symlink, single-link regular file."""
    try:
        descriptor = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise UnsafeEvidencePathError(display_path) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise UnsafeEvidencePathError(display_path)
        if before.st_size > maximum_bytes:
            raise EvidenceResourceLimitError(display_path)
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
            if size > maximum_bytes:
                raise EvidenceResourceLimitError(display_path)
        after = os.fstat(descriptor)
        stable_fields_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        stable_fields_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if stable_fields_before != stable_fields_after or size != after.st_size:
            raise UnstableEvidenceFileError(display_path)
        return ScannedFile(sha256=digest.hexdigest(), size_bytes=size)
    finally:
        os.close(descriptor)


def read_regular_file_at(
    parent_fd: int,
    name: str,
    *,
    display_path: str,
    maximum_bytes: int,
) -> bytes:
    """Read one bounded, stable regular file without following links."""
    try:
        descriptor = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise UnsafeEvidencePathError(display_path) from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > maximum_bytes
        ):
            raise UnsafeEvidencePathError(display_path)
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, min(1024 * 1024, maximum_bytes + 1)):
            size += len(chunk)
            if size > maximum_bytes:
                raise UnsafeEvidencePathError(display_path)
            chunks.append(chunk)
        after = os.fstat(descriptor)
        stable_fields_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        stable_fields_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if stable_fields_before != stable_fields_after or size != after.st_size:
            raise UnstableEvidenceFileError(display_path)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def scan_regular_files(
    directory_fd: int,
    *,
    exclude_root_manifest: bool,
) -> dict[str, ScannedFile]:
    """Recursively inventory regular files without following directory links."""
    result: dict[str, ScannedFile] = {}
    context = _ScanContext(
        exclude_root_manifest=exclude_root_manifest,
        result=result,
        budget=_ScanBudget(),
    )
    _scan_directory(
        directory_fd,
        prefix=(),
        context=context,
    )
    return result


def _scan_directory(
    directory_fd: int,
    *,
    prefix: tuple[str, ...],
    context: _ScanContext,
) -> None:
    names = _bounded_directory_names(
        directory_fd,
        prefix=prefix,
        budget=context.budget,
        excluded_name=(
            MANIFEST_FILENAME if not prefix and context.exclude_root_manifest else None
        ),
    )
    for name in names:
        _scan_entry(
            directory_fd,
            name,
            prefix=prefix,
            context=context,
        )


def _bounded_directory_names(
    directory_fd: int,
    *,
    prefix: tuple[str, ...],
    budget: _ScanBudget,
    excluded_name: str | None,
) -> list[str]:
    try:
        names: list[str] = []
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                names.append(entry.name)
                if entry.name != excluded_name:
                    budget.entries += 1
                    if budget.entries > MAX_SCAN_ENTRIES:
                        raise EvidenceResourceLimitError("/".join(prefix) or None)
    except OSError as exc:
        if isinstance(exc, EvidenceResourceLimitError):
            raise
        display_path = "/".join(prefix) or None
        raise UnsafeEvidencePathError(display_path) from exc
    return sorted(names)


def _scan_entry(
    directory_fd: int,
    name: str,
    *,
    prefix: tuple[str, ...],
    context: _ScanContext,
) -> None:
    relative_parts = (*prefix, name)
    relative_path = "/".join(relative_parts)
    if (
        len(relative_parts) > MAX_ARTIFACT_PATH_COMPONENTS
        or len(relative_path) > MAX_ARTIFACT_PATH_LENGTH
    ):
        raise EvidenceResourceLimitError(relative_path)
    try:
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise UnsafeEvidencePathError(relative_path) from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise UnsafeEvidencePathError(relative_path)
    if not prefix and context.exclude_root_manifest and name == MANIFEST_FILENAME:
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise UnsafeEvidencePathError(relative_path)
        return
    if stat.S_ISDIR(metadata.st_mode):
        _scan_child_directory(
            directory_fd,
            name,
            relative_parts=relative_parts,
            relative_path=relative_path,
            context=context,
        )
        return
    if not stat.S_ISREG(metadata.st_mode):
        raise UnsafeEvidencePathError(relative_path)
    _scan_regular_entry(
        directory_fd,
        name,
        relative_path=relative_path,
        context=context,
    )


def _scan_child_directory(
    directory_fd: int,
    name: str,
    *,
    relative_parts: tuple[str, ...],
    relative_path: str,
    context: _ScanContext,
) -> None:
    child_fd = open_directory_at(directory_fd, name, display_path=relative_path)
    try:
        _scan_directory(
            child_fd,
            prefix=relative_parts,
            context=context,
        )
    finally:
        os.close(child_fd)


def _scan_regular_entry(
    directory_fd: int,
    name: str,
    *,
    relative_path: str,
    context: _ScanContext,
) -> None:
    scanned = hash_file_at(directory_fd, name, display_path=relative_path)
    context.budget.artifact_bytes += scanned.size_bytes
    if context.budget.artifact_bytes > MAX_RUN_ARTIFACT_BYTES:
        raise EvidenceResourceLimitError(relative_path)
    context.result[relative_path] = scanned
