"""Read-only offline integrity verification for finalized evidence runs."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import final

from cai_verify.evidence._filesystem import (
    EvidenceResourceLimitError,
    ScannedFile,
    UnsafeEvidencePathError,
    UnstableEvidenceFileError,
    open_anchored_directory,
    read_regular_file_at,
    scan_regular_files,
)
from cai_verify.evidence.models import (
    MANIFEST_FILENAME,
    MAX_MANIFEST_BYTES,
    IntegrityIssue,
    IntegrityIssueCode,
    IntegrityVerification,
    ManifestValidationError,
    NonCanonicalManifestError,
    RunManifest,
)


@final
@dataclass(frozen=True, slots=True)
class _LoadedManifest:
    manifest: RunManifest
    sha256: str


@final
@dataclass(frozen=True, slots=True)
class _ScannedArtifacts:
    files: dict[str, ScannedFile]


def verify_run_integrity(
    run_directory: str | os.PathLike[str],
) -> IntegrityVerification:
    """Verify a run without modifying it or following any symlink."""
    run_path = Path(
        os.path.abspath(  # noqa: PTH100 - must not follow untrusted symlinks
            os.fspath(run_directory)
        )
    )
    try:
        run_fd = open_anchored_directory(run_path)
    except UnsafeEvidencePathError:
        return _failure(IntegrityIssueCode.UNSAFE_PATH)

    try:
        loaded = _load_manifest(run_fd)
        if isinstance(loaded, IntegrityVerification):
            return loaded
        scanned = _scan_artifacts(run_fd, loaded)
        if isinstance(scanned, IntegrityVerification):
            return scanned
        confirmed = _load_manifest(run_fd)
        if isinstance(confirmed, IntegrityVerification):
            return confirmed
        if confirmed.sha256 != loaded.sha256:
            return _artifact_scan_failure(
                loaded,
                IntegrityIssueCode.UNSTABLE_ARTIFACT,
                MANIFEST_FILENAME,
            )
        return _compare_artifacts(loaded, scanned)
    finally:
        os.close(run_fd)


def _load_manifest(run_fd: int) -> _LoadedManifest | IntegrityVerification:
    try:
        manifest_bytes = read_regular_file_at(
            run_fd,
            MANIFEST_FILENAME,
            display_path=MANIFEST_FILENAME,
            maximum_bytes=MAX_MANIFEST_BYTES,
        )
    except FileNotFoundError:
        return _failure(IntegrityIssueCode.MISSING_MANIFEST)
    except UnstableEvidenceFileError:
        return _failure(
            IntegrityIssueCode.UNSTABLE_ARTIFACT,
            path=MANIFEST_FILENAME,
        )
    except UnsafeEvidencePathError:
        return _failure(IntegrityIssueCode.UNSAFE_PATH, path=MANIFEST_FILENAME)

    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    try:
        manifest = RunManifest.from_bytes(manifest_bytes)
    except NonCanonicalManifestError:
        return _invalid_manifest(
            IntegrityIssueCode.NON_CANONICAL_MANIFEST,
            manifest_sha256,
        )
    except ManifestValidationError:
        return _invalid_manifest(
            IntegrityIssueCode.INVALID_MANIFEST,
            manifest_sha256,
        )
    return _LoadedManifest(manifest=manifest, sha256=manifest_sha256)


def _scan_artifacts(
    run_fd: int,
    loaded: _LoadedManifest,
) -> _ScannedArtifacts | IntegrityVerification:
    try:
        actual = scan_regular_files(run_fd, exclude_root_manifest=True)
    except UnstableEvidenceFileError as exc:
        return _artifact_scan_failure(
            loaded,
            IntegrityIssueCode.UNSTABLE_ARTIFACT,
            exc.path,
        )
    except UnsafeEvidencePathError as exc:
        return _artifact_scan_failure(
            loaded,
            IntegrityIssueCode.UNSAFE_PATH,
            exc.path,
        )
    except EvidenceResourceLimitError as exc:
        return _artifact_scan_failure(
            loaded,
            IntegrityIssueCode.RESOURCE_LIMIT,
            exc.path,
        )
    return _ScannedArtifacts(files=actual)


def _compare_artifacts(
    loaded: _LoadedManifest,
    scanned: _ScannedArtifacts,
) -> IntegrityVerification:
    expected = {artifact.path: artifact for artifact in loaded.manifest.artifacts}
    actual = scanned.files
    issues = [
        IntegrityIssue(code=IntegrityIssueCode.MISSING_ARTIFACT, path=path)
        for path in sorted(set(expected) - set(actual))
    ]
    issues.extend(
        IntegrityIssue(code=IntegrityIssueCode.UNEXPECTED_ARTIFACT, path=path)
        for path in sorted(set(actual) - set(expected))
    )
    common_paths = sorted(set(expected) & set(actual))
    for path in common_paths:
        expected_artifact = expected[path]
        actual_artifact = actual[path]
        if actual_artifact.size_bytes != expected_artifact.size_bytes:
            issues.append(
                IntegrityIssue(code=IntegrityIssueCode.SIZE_MISMATCH, path=path)
            )
        if actual_artifact.sha256 != expected_artifact.sha256:
            issues.append(
                IntegrityIssue(code=IntegrityIssueCode.DIGEST_MISMATCH, path=path)
            )
    return IntegrityVerification(
        run_id=loaded.manifest.run_id,
        manifest_sha256=loaded.sha256,
        artifacts_checked=len(common_paths),
        issues=tuple(issues),
    )


def _invalid_manifest(
    code: IntegrityIssueCode,
    manifest_sha256: str,
) -> IntegrityVerification:
    return IntegrityVerification(
        run_id=None,
        manifest_sha256=manifest_sha256,
        artifacts_checked=0,
        issues=(IntegrityIssue(code=code),),
    )


def _artifact_scan_failure(
    loaded: _LoadedManifest,
    code: IntegrityIssueCode,
    path: str | None,
) -> IntegrityVerification:
    return IntegrityVerification(
        run_id=loaded.manifest.run_id,
        manifest_sha256=loaded.sha256,
        artifacts_checked=0,
        issues=(IntegrityIssue(code=code, path=path),),
    )


def _failure(
    code: IntegrityIssueCode,
    *,
    path: str | None = None,
) -> IntegrityVerification:
    return IntegrityVerification(
        run_id=None,
        manifest_sha256=None,
        artifacts_checked=0,
        issues=(IntegrityIssue(code=code, path=path),),
    )
