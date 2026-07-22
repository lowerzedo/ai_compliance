"""Versioned, deterministic evidence-manifest models."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, cast, final

MANIFEST_SCHEMA_VERSION = "1"
MANIFEST_FILENAME = "manifest.json"
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_ARTIFACTS = 10_000
MAX_ARTIFACT_PATH_LENGTH = 1024
MAX_ARTIFACT_PATH_COMPONENTS = 32
MAX_MEDIA_TYPE_LENGTH = 255
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_RUN_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_SCAN_ENTRIES = MAX_MANIFEST_ARTIFACTS * 2

_RUN_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_PATH_COMPONENT_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_MEDIA_TYPE_PATTERN = re.compile(
    r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+\Z",
)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


class Sensitivity(StrEnum):
    """Sensitivity classification recorded for every run artifact."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class IntegrityIssueCode(StrEnum):
    """Stable categories returned by offline integrity verification."""

    MISSING_MANIFEST = "missing_manifest"
    INVALID_MANIFEST = "invalid_manifest"
    NON_CANONICAL_MANIFEST = "non_canonical_manifest"
    UNSAFE_PATH = "unsafe_path"
    MISSING_ARTIFACT = "missing_artifact"
    UNEXPECTED_ARTIFACT = "unexpected_artifact"
    SIZE_MISMATCH = "size_mismatch"
    DIGEST_MISMATCH = "digest_mismatch"
    UNSTABLE_ARTIFACT = "unstable_artifact"
    RESOURCE_LIMIT = "resource_limit"


class ManifestValidationError(ValueError):
    """Raised when manifest bytes do not satisfy the exact versioned contract."""


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class ManifestArtifact:
    """One exact stored file inventoried by a run manifest."""

    path: str
    media_type: str
    sensitivity: Sensitivity
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        """Validate portable paths, metadata, digest, and byte size."""
        validate_artifact_path(self.path)
        validate_media_type(self.media_type)
        if not isinstance(self.sensitivity, Sensitivity):
            message = "sensitivity must be a Sensitivity"
            raise TypeError(message)
        if (
            not isinstance(self.sha256, str)
            or _SHA256_PATTERN.fullmatch(self.sha256) is None
        ):
            message = "sha256 must be a lowercase hexadecimal SHA-256 digest"
            raise ValueError(message)
        if isinstance(self.size_bytes, bool) or not isinstance(self.size_bytes, int):
            message = "size_bytes must be an integer"
            raise TypeError(message)
        if self.size_bytes < 0:
            message = "size_bytes must not be negative"
            raise ValueError(message)
        if self.size_bytes > MAX_ARTIFACT_BYTES:
            message = "size_bytes exceeds the maximum artifact size"
            raise ValueError(message)

    def to_dict(self) -> dict[str, str | int]:
        """Return the canonical JSON-compatible artifact representation."""
        return {
            "media_type": self.media_type,
            "path": self.path,
            "sensitivity": self.sensitivity.value,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class RunManifest:
    """Canonical inventory of every non-manifest file in one finalized run."""

    run_id: str
    artifacts: tuple[ManifestArtifact, ...]
    schema_version: str = MANIFEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        """Enforce the immutable schema and deterministic artifact ordering."""
        validate_run_id(self.run_id)
        if self.schema_version != MANIFEST_SCHEMA_VERSION:
            message = f"schema_version must be {MANIFEST_SCHEMA_VERSION!r}"
            raise ValueError(message)
        if not isinstance(self.artifacts, tuple) or not all(
            type(artifact) is ManifestArtifact for artifact in self.artifacts
        ):
            message = "artifacts must be a tuple of ManifestArtifact values"
            raise TypeError(message)
        if len(self.artifacts) > MAX_MANIFEST_ARTIFACTS:
            message = "manifest contains too many artifacts"
            raise ValueError(message)
        if sum(artifact.size_bytes for artifact in self.artifacts) > (
            MAX_RUN_ARTIFACT_BYTES
        ):
            message = "manifest artifact bytes exceed the maximum run size"
            raise ValueError(message)
        paths = [artifact.path for artifact in self.artifacts]
        if len(paths) != len(set(paths)):
            message = "manifest artifact paths must be unique"
            raise ValueError(message)
        object.__setattr__(
            self,
            "artifacts",
            tuple(sorted(self.artifacts, key=lambda artifact: artifact.path)),
        )

    def to_dict(self) -> dict[str, object]:
        """Return the exact versioned manifest representation."""
        return {
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "run_id": self.run_id,
            "schema_version": self.schema_version,
        }

    def to_bytes(self) -> bytes:
        """Serialize to deterministic UTF-8 bytes without a trailing newline."""
        return json.dumps(
            self.to_dict(),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def from_bytes(cls, content: bytes) -> RunManifest:
        """Strictly parse one canonical manifest without accepting extensions."""
        if not isinstance(content, bytes):
            message = "manifest content must be bytes"
            raise TypeError(message)
        if not content:
            message = "manifest must not be empty"
            raise ManifestValidationError(message)
        if len(content) > MAX_MANIFEST_BYTES:
            message = "manifest exceeds the maximum supported size"
            raise ManifestValidationError(message)
        try:
            decoded = content.decode("utf-8")
            value = json.loads(decoded, object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            message = "manifest is not valid duplicate-free UTF-8 JSON"
            raise ManifestValidationError(message) from exc
        manifest = cls._from_json_value(value)
        if manifest.to_bytes() != content:
            message = "manifest JSON is not in canonical form"
            raise NonCanonicalManifestError(message)
        return manifest

    @classmethod
    def _from_json_value(cls, value: object) -> RunManifest:
        if not isinstance(value, dict) or set(value) != {
            "artifacts",
            "run_id",
            "schema_version",
        }:
            message = "manifest must contain exactly the versioned top-level fields"
            raise ManifestValidationError(message)
        run_id = value["run_id"]
        schema_version = value["schema_version"]
        raw_artifacts = value["artifacts"]
        if not isinstance(run_id, str) or not isinstance(schema_version, str):
            message = "manifest run_id and schema_version must be strings"
            raise ManifestValidationError(message)
        if not isinstance(raw_artifacts, list):
            message = "manifest artifacts must be an array"
            raise ManifestValidationError(message)
        if len(raw_artifacts) > MAX_MANIFEST_ARTIFACTS:
            message = "manifest contains too many artifacts"
            raise ManifestValidationError(message)
        artifacts = tuple(_parse_artifact(item) for item in raw_artifacts)
        try:
            return cls(
                run_id=run_id,
                schema_version=schema_version,
                artifacts=artifacts,
            )
        except (TypeError, ValueError) as exc:
            message = "manifest contains invalid field values"
            raise ManifestValidationError(message) from exc


class NonCanonicalManifestError(ManifestValidationError):
    """Raised when valid manifest data is not encoded canonically."""


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class IntegrityIssue:
    """One deterministic, non-sensitive offline verification finding."""

    code: IntegrityIssueCode
    path: str | None = None


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class IntegrityVerification:
    """Read-only integrity result for one evidence run."""

    run_id: str | None
    manifest_sha256: str | None
    artifacts_checked: int
    issues: tuple[IntegrityIssue, ...]

    @property
    def valid(self) -> bool:
        """Return whether the manifest and all inventoried bytes verified."""
        return not self.issues


def validate_run_id(run_id: object) -> str:
    """Validate one portable run-directory component."""
    if not isinstance(run_id, str) or _RUN_ID_PATTERN.fullmatch(run_id) is None:
        message = "run_id must be one portable 1-128 character path component"
        raise ValueError(message)
    return run_id


def validate_artifact_path(path: object) -> tuple[str, ...]:
    """Reject absolute, ambiguous, reserved, and traversing artifact paths."""
    if not isinstance(path, str):
        message = "artifact path must be a string"
        raise TypeError(message)
    if not path or len(path) > MAX_ARTIFACT_PATH_LENGTH or path.startswith(("/", "\\")):
        message = "artifact path must be a non-empty relative path"
        raise ValueError(message)
    if "\\" in path or "\x00" in path:
        message = "artifact path must use portable forward-slash components"
        raise ValueError(message)
    components = path.split("/")
    if len(components) > MAX_ARTIFACT_PATH_COMPONENTS or any(
        component in {"", ".", ".."}
        or _PATH_COMPONENT_PATTERN.fullmatch(component) is None
        for component in components
    ):
        message = "artifact path contains an invalid or traversing component"
        raise ValueError(message)
    if components[0] == ".cai-staging" or path == MANIFEST_FILENAME:
        message = "artifact path is reserved by the evidence store"
        raise ValueError(message)
    return tuple(components)


def validate_media_type(media_type: object) -> str:
    """Require a normalized lowercase type/subtype without parameters."""
    if (
        not isinstance(media_type, str)
        or len(media_type) > MAX_MEDIA_TYPE_LENGTH
        or _MEDIA_TYPE_PATTERN.fullmatch(media_type) is None
    ):
        message = "media_type must be a lowercase type/subtype"
        raise ValueError(message)
    return media_type


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            message = "manifest objects must not contain duplicate keys"
            raise ManifestValidationError(message)
        result[key] = value
    return result


def _parse_artifact(value: object) -> ManifestArtifact:
    expected_fields = {"media_type", "path", "sensitivity", "sha256", "size_bytes"}
    if not isinstance(value, dict) or set(value) != expected_fields:
        message = "manifest artifacts must contain exactly the versioned fields"
        raise ManifestValidationError(message)
    try:
        sensitivity = Sensitivity(value["sensitivity"])
    except (TypeError, ValueError) as exc:
        message = "manifest artifact sensitivity is invalid"
        raise ManifestValidationError(message) from exc
    try:
        return ManifestArtifact(
            path=cast("str", value["path"]),
            media_type=cast("str", value["media_type"]),
            sensitivity=sensitivity,
            sha256=cast("str", value["sha256"]),
            size_bytes=cast("int", value["size_bytes"]),
        )
    except (TypeError, ValueError) as exc:
        message = "manifest artifact contains invalid field values"
        raise ManifestValidationError(message) from exc
