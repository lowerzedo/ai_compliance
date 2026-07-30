"""Bounded, manifest-verified views of reciprocal AWS evidence history."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, cast, final

from cai_verify.assertions.retrieval import (
    RETRIEVAL_BOUNDARY_EVALUATOR_VERSION,
    RETRIEVAL_BOUNDARY_FIXED_LIMITATIONS,
)
from cai_verify.aws._reciprocal_evidence import (
    AWS_RECIPROCAL_BUNDLE_KIND,
    AWS_RECIPROCAL_EVIDENCE_SCHEMA_VERSION,
)
from cai_verify.core import (
    ASSERTION_RESULT_SCHEMA_VERSION,
    AssertionStatus,
    AssertionType,
    JsonValue,
    aggregate_statuses,
    exit_code_for_status,
)
from cai_verify.evidence._filesystem import (
    ScannedFile,
    UnsafeEvidencePathError,
    UnstableEvidenceFileError,
    hash_file_at,
    open_anchored_directory,
    open_directory_at,
    read_regular_file_at,
)
from cai_verify.evidence.models import (
    MANIFEST_FILENAME,
    RunManifest,
    Sensitivity,
    validate_run_id,
)

EVIDENCE_HISTORY_SCHEMA_VERSION = "1"
MAX_EVIDENCE_HISTORY_RUNS = 1_000
MAX_EVIDENCE_HISTORY_PAGE_SIZE = 50

_MAX_HISTORY_MANIFEST_BYTES = 16 * 1024
_MAX_HISTORY_ARTIFACTS = 9
_MAX_HISTORY_TOTAL_BYTES = 512 * 1024
_MAX_RUN_METADATA_BYTES = 16 * 1024
_MAX_PUBLIC_REPORT_BYTES = 128 * 1024
_MAX_TERMINAL_REPORT_BYTES = 16 * 1024
_MAX_NORMALIZED_ARTIFACT_BYTES = 64 * 1024
_EXPECTED_ROOT_ENTRY_COUNT = 6
_EXPECTED_ITEM_COUNT = 2
_MAX_IDENTIFIER_LENGTH = 256
_MAX_STATUS_REASON_LENGTH = 512
_MAX_NORMALIZED_STATE_LENGTH = 128
_PAIR_SIZE = 2
_MAX_EVIDENCE_IDS = 2
_MAX_RETRIEVED_ITEMS = 10_000
_UTC_MICROSECOND_TIMESTAMP_LENGTH = 27
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_AWS_REGION_PATTERN = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-\d\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_NORMALIZED_STATE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
_OPAQUE_RUN_ID_PATTERN = re.compile(r"run-[0-9a-f]{32}\Z")
_SAFE_UI_RUN_ID_PATTERN = re.compile(r"ui-\d{8}T\d{12}Z-[0-9a-f]{32}\Z")
_SUPPORTED_ENVIRONMENTS = frozenset({"sandbox", "development", "staging"})
_ITEM_NAME_PATTERN = re.compile(r"item-[0-9a-f]{16}\.json\Z")
_ROOT_ENTRY_NAMES = frozenset(
    {
        MANIFEST_FILENAME,
        "actions",
        "probes",
        "reports",
        "results",
        "run.json",
    }
)
_ITEM_DIRECTORY_NAMES = ("actions", "probes", "results")
_REPORT_ENTRY_NAMES = frozenset({"report.json", "terminal.txt"})
_OPAQUE_RUN_KEY = secrets.token_bytes(32)
_SUPPORTED_ASSERTION_STATUSES = frozenset(
    {
        AssertionStatus.PASS,
        AssertionStatus.FAIL,
        AssertionStatus.INCONCLUSIVE,
        AssertionStatus.ERROR,
    }
)
_RUN_FIELDS = frozenset(
    {
        "action_ids",
        "aggregate_status",
        "assertion_ids",
        "bundle_kind",
        "evidence_schema_version",
        "probe_ids",
        "run_id",
        "scenario_id",
        "target_environment",
        "target_pseudonym_sha256",
        "target_region",
    }
)
_REPORT_FIELDS = frozenset(
    {"aggregate_status", "exit_code", "results", "run_id", "schema_version"}
)
_RESULT_FIELDS = frozenset(
    {
        "assertion_id",
        "assertion_type",
        "evaluation_completed_at",
        "evaluation_started_at",
        "evaluator_version",
        "evidence_ids",
        "expected",
        "limitations",
        "observed",
        "schema_version",
        "status",
        "status_reason",
    }
)
_EXPECTED_FIELDS = frozenset(
    {
        "baseline_canary_observed",
        "boundary_canary_observed",
        "complete_context_scan_succeeded",
        "exactly_one_correlated_retrieval_record",
        "pre_generation_phase_matched",
        "retrieval_path_exercised",
        "retrieval_succeeded",
        "undeclared_synthetic_marker_observed",
    }
)
_OBSERVED_FIELDS = frozenset(
    {
        "baseline_canary_observed",
        "boundary_canary_observed",
        "normalized_evidence_state",
        "retrieval_path_exercised",
        "retrieved_item_count",
        "undeclared_synthetic_marker_observed",
    }
)
_EXPECTED_VALUES = {
    "baseline_canary_observed": True,
    "boundary_canary_observed": False,
    "complete_context_scan_succeeded": True,
    "exactly_one_correlated_retrieval_record": True,
    "pre_generation_phase_matched": True,
    "retrieval_path_exercised": True,
    "retrieval_succeeded": True,
    "undeclared_synthetic_marker_observed": False,
}
_NULLABLE_OBSERVED_BOOLEANS = (
    "baseline_canary_observed",
    "boundary_canary_observed",
    "undeclared_synthetic_marker_observed",
)
_STATE_ISSUES: dict[EvidenceHistoryState, tuple[str, ...]]


class EvidenceHistoryState(StrEnum):
    """Stable, non-sensitive state of one evidence-history entry."""

    VERIFIED = "verified"
    TAMPERED = "tampered"
    MALFORMED = "malformed"
    UNSUPPORTED = "unsupported"
    UNFINALIZED = "unfinalized"


_STATE_ISSUES = {
    EvidenceHistoryState.VERIFIED: (),
    EvidenceHistoryState.TAMPERED: ("integrity_failed",),
    EvidenceHistoryState.MALFORMED: ("malformed_bundle",),
    EvidenceHistoryState.UNSUPPORTED: ("unsupported_bundle",),
    EvidenceHistoryState.UNFINALIZED: ("missing_manifest",),
}


class EvidenceHistoryError(RuntimeError):
    """Base class for fixed, non-sensitive evidence-history failures."""


class InvalidEvidenceHistoryRequestError(EvidenceHistoryError):
    """Raised when pagination or run selection is invalid."""

    def __init__(self) -> None:
        """Use one fixed message that cannot echo request data."""
        super().__init__("invalid evidence history request")


class EvidenceHistoryLimitError(EvidenceHistoryError):
    """Raised when the evidence root exceeds the fixed run-count limit."""

    def __init__(self) -> None:
        """Use one fixed message without filesystem names."""
        super().__init__("evidence history exceeds the supported run limit")


class UnsafeEvidenceHistoryError(EvidenceHistoryError):
    """Raised when the evidence root contains an unsafe filesystem object."""

    def __init__(self) -> None:
        """Use one fixed message without filesystem names."""
        super().__init__("evidence history contains an unsafe path")


class EvidenceHistoryRunNotFoundError(EvidenceHistoryError):
    """Raised when a selected validated run is not present."""

    def __init__(self) -> None:
        """Use one fixed message without the selected run identifier."""
        super().__init__("evidence history run was not found")


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceHistoryResultSummary:
    """Safe result fields extracted from one verified public report."""

    assertion_id: str
    status: AssertionStatus

    def to_dict(self) -> dict[str, JsonValue]:
        """Return the internal localhost API representation."""
        return {
            "assertionId": self.assertion_id,
            "status": self.status.value,
        }


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceHistoryReport:
    """Safe, bounded result summary from a verified reciprocal report."""

    results: tuple[EvidenceHistoryResultSummary, ...]

    def to_dict(self) -> dict[str, JsonValue]:
        """Return the internal localhost API representation."""
        return {"results": [result.to_dict() for result in self.results]}


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceHistoryRecord:
    """One normalized history entry with sensitive source fields omitted."""

    run_id: str = field(repr=False)
    state: EvidenceHistoryState
    aggregate_status: AssertionStatus | None = None
    scenario_id: str | None = None
    target_region: str | None = None
    issues: tuple[str, ...] = ()
    evidence_path: str | None = field(default=None, repr=False)
    report: EvidenceHistoryReport | None = None

    def to_dict(self) -> dict[str, JsonValue]:
        """Return the fixed internal localhost API representation."""
        return {
            "aggregateStatus": (
                self.aggregate_status.value
                if self.aggregate_status is not None
                else None
            ),
            "evidencePath": self.evidence_path,
            "issues": list(self.issues),
            "report": self.report.to_dict() if self.report is not None else None,
            "runId": self.run_id,
            "scenarioId": self.scenario_id,
            "state": self.state.value,
            "targetRegion": self.target_region,
        }


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceHistoryPage:
    """One deterministic cursor page of bounded history records."""

    items: tuple[EvidenceHistoryRecord, ...]
    next_cursor: str | None

    def to_dict(self) -> dict[str, JsonValue]:
        """Return the fixed internal localhost API representation."""
        return {
            "items": [item.to_dict() for item in self.items],
            "nextCursor": self.next_cursor,
            "schemaVersion": EVIDENCE_HISTORY_SCHEMA_VERSION,
        }


@dataclass(frozen=True, slots=True)
class _RunMetadata:
    run_id: str = field(repr=False)
    scenario_id: str = field(repr=False)
    aggregate_status: AssertionStatus
    target_region: str
    action_ids: tuple[str, str] = field(repr=False)
    probe_ids: tuple[str, str] = field(repr=False)
    assertion_ids: tuple[str, str] = field(repr=False)


@dataclass(frozen=True, slots=True)
class _ActualInventory:
    artifact_sizes: dict[str, int]


@dataclass(frozen=True, slots=True)
class _ParsedResult:
    assertion_id: str = field(repr=False)
    status: AssertionStatus


class _MalformedBundleError(ValueError):
    pass


class _UnsupportedBundleError(ValueError):
    pass


class _ChangedBundleError(OSError):
    pass


def list_evidence_history(
    evidence_root: str | os.PathLike[str],
    *,
    cursor: str | None = None,
    limit: int = MAX_EVIDENCE_HISTORY_PAGE_SIZE,
) -> EvidenceHistoryPage:
    """List one deterministic page without following filesystem links."""
    page_limit = _validated_page_limit(limit)
    root = _absolute_path(evidence_root)
    run_ids = _bounded_run_ids(root)
    start = _cursor_start(run_ids, cursor)
    selected_ids = run_ids[start : start + page_limit]
    items = tuple(
        _inspect_run(root, run_id, record_id=_public_run_id(run_id))
        for run_id in selected_ids
    )
    has_more = start + len(selected_ids) < len(run_ids)
    next_cursor = (
        _public_run_id(selected_ids[-1]) if selected_ids and has_more else None
    )
    return EvidenceHistoryPage(items=items, next_cursor=next_cursor)


def get_evidence_history_record(
    evidence_root: str | os.PathLike[str],
    run_id: str,
) -> EvidenceHistoryRecord:
    """Inspect one opaque run selection after applying root-wide bounds."""
    if type(run_id) is not str:
        raise InvalidEvidenceHistoryRequestError
    root = _absolute_path(evidence_root)
    run_ids = _bounded_run_ids(root)
    selected = _resolve_public_run_id(run_ids, run_id)
    if selected is None:
        raise EvidenceHistoryRunNotFoundError
    return _inspect_run(root, selected, record_id=run_id)


def verify_generated_evidence_run(
    evidence_root: str | os.PathLike[str],
    raw_run_id: str,
) -> EvidenceHistoryRecord:
    """Inspect one trusted-format UI run without exposing its raw identifier."""
    if (
        type(raw_run_id) is not str
        or _SAFE_UI_RUN_ID_PATTERN.fullmatch(raw_run_id) is None
    ):
        raise InvalidEvidenceHistoryRequestError
    root = _absolute_path(evidence_root)
    try:
        root_fd = open_anchored_directory(root)
    except UnsafeEvidencePathError as exc:
        if _caused_by_file_not_found(exc):
            raise EvidenceHistoryRunNotFoundError from exc
        raise UnsafeEvidenceHistoryError from exc
    try:
        try:
            metadata = os.stat(raw_run_id, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise EvidenceHistoryRunNotFoundError from exc
        except OSError as exc:
            raise UnsafeEvidenceHistoryError from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise UnsafeEvidenceHistoryError
    finally:
        os.close(root_fd)
    return _inspect_run(
        root,
        raw_run_id,
        record_id=raw_run_id,
    )


def _validated_page_limit(value: object) -> int:
    if type(value) is not int or value < 1 or value > MAX_EVIDENCE_HISTORY_PAGE_SIZE:
        raise InvalidEvidenceHistoryRequestError
    return value


def _absolute_path(value: str | os.PathLike[str]) -> Path:
    try:
        return Path(
            os.path.abspath(  # noqa: PTH100 - do not resolve untrusted symlinks.
                os.fspath(value)
            )
        )
    except (TypeError, ValueError, OSError) as exc:
        raise UnsafeEvidenceHistoryError from exc


def _bounded_run_ids(root: Path) -> tuple[str, ...]:
    try:
        root_fd = open_anchored_directory(root)
    except UnsafeEvidencePathError as exc:
        if _caused_by_file_not_found(exc):
            return ()
        raise UnsafeEvidenceHistoryError from exc
    try:
        names: list[str] = []
        try:
            with os.scandir(root_fd) as entries:
                for entry in entries:
                    names.append(entry.name)
                    if len(names) > MAX_EVIDENCE_HISTORY_RUNS:
                        break
        except OSError as exc:
            raise UnsafeEvidenceHistoryError from exc
        if len(names) > MAX_EVIDENCE_HISTORY_RUNS:
            raise EvidenceHistoryLimitError
        for name in sorted(names):
            _validate_root_entry(root_fd, name)
        return tuple(sorted(names, reverse=True))
    finally:
        os.close(root_fd)


def _validate_root_entry(root_fd: int, name: str) -> None:
    try:
        validate_run_id(name)
        metadata = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    except (OSError, TypeError, ValueError) as exc:
        raise UnsafeEvidenceHistoryError from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise UnsafeEvidenceHistoryError


def _cursor_start(run_ids: tuple[str, ...], cursor: str | None) -> int:
    if cursor is None:
        return 0
    if type(cursor) is not str:
        raise InvalidEvidenceHistoryRequestError
    selected = _resolve_public_run_id(run_ids, cursor)
    if selected is None:
        raise InvalidEvidenceHistoryRequestError
    return run_ids.index(selected) + 1


def _opaque_run_id(run_id: str) -> str:
    digest = hmac.new(
        _OPAQUE_RUN_KEY,
        run_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:32]
    return f"run-{digest}"


def _public_run_id(run_id: str) -> str:
    if _SAFE_UI_RUN_ID_PATTERN.fullmatch(run_id) is not None:
        return run_id
    return _opaque_run_id(run_id)


def _resolve_public_run_id(
    run_ids: tuple[str, ...],
    public_run_id: str,
) -> str | None:
    if _SAFE_UI_RUN_ID_PATTERN.fullmatch(public_run_id) is not None:
        return public_run_id if public_run_id in run_ids else None
    if _OPAQUE_RUN_ID_PATTERN.fullmatch(public_run_id) is None:
        raise InvalidEvidenceHistoryRequestError
    matches = tuple(
        run_id
        for run_id in run_ids
        if _SAFE_UI_RUN_ID_PATTERN.fullmatch(run_id) is None
        and hmac.compare_digest(_opaque_run_id(run_id), public_run_id)
    )
    return matches[0] if len(matches) == 1 else None


def _inspect_run(  # noqa: C901, PLR0911 - explicit fail-closed states.
    root: Path,
    run_id: str,
    *,
    record_id: str,
) -> EvidenceHistoryRecord:
    run_path = root / run_id
    try:
        manifest = _preflight_manifest(run_path, run_id)
    except FileNotFoundError:
        return _state_record(record_id, EvidenceHistoryState.UNFINALIZED)
    except _UnsupportedBundleError:
        return _state_record(record_id, EvidenceHistoryState.UNSUPPORTED)
    except _MalformedBundleError:
        return _state_record(record_id, EvidenceHistoryState.MALFORMED)
    except _ChangedBundleError:
        return _state_record(record_id, EvidenceHistoryState.TAMPERED)

    manifest_sha256 = _manifest_sha256(manifest)
    if _bounded_verification_state(run_path, manifest, manifest_sha256) is not None:
        return _state_record(record_id, EvidenceHistoryState.TAMPERED)

    try:
        run_content = _read_root_file(
            run_path,
            "run.json",
            maximum_bytes=_MAX_RUN_METADATA_BYTES,
        )
    except FileNotFoundError:
        return _confirmed_state_record(
            run_path,
            record_id,
            manifest,
            manifest_sha256,
            EvidenceHistoryState.UNSUPPORTED,
        )
    except _MalformedBundleError:
        return _confirmed_state_record(
            run_path,
            record_id,
            manifest,
            manifest_sha256,
            EvidenceHistoryState.MALFORMED,
        )
    except _ChangedBundleError:
        return _state_record(record_id, EvidenceHistoryState.TAMPERED)

    try:
        _require_manifest_bytes(manifest, "run.json", run_content)
        run_value = _load_json_object(run_content)
        metadata = _parse_run_metadata(run_value, run_id)
        _validate_manifest_contract(manifest, metadata)
        report_content = _read_report_file(run_path)
        _require_manifest_bytes(manifest, "reports/report.json", report_content)
        report = _parse_public_report(
            _load_json_object(report_content),
            metadata,
        )
    except _UnsupportedBundleError:
        return _confirmed_state_record(
            run_path,
            record_id,
            manifest,
            manifest_sha256,
            EvidenceHistoryState.UNSUPPORTED,
        )
    except _MalformedBundleError:
        return _confirmed_state_record(
            run_path,
            record_id,
            manifest,
            manifest_sha256,
            EvidenceHistoryState.MALFORMED,
        )
    except _ChangedBundleError:
        return _state_record(record_id, EvidenceHistoryState.TAMPERED)

    if _bounded_verification_state(run_path, manifest, manifest_sha256) is not None:
        return _state_record(record_id, EvidenceHistoryState.TAMPERED)
    return EvidenceHistoryRecord(
        run_id=record_id,
        state=EvidenceHistoryState.VERIFIED,
        aggregate_status=metadata.aggregate_status,
        scenario_id="scenario-01",
        target_region=metadata.target_region,
        issues=(),
        evidence_path=(
            str(run_path)
            if _SAFE_UI_RUN_ID_PATTERN.fullmatch(run_id) is not None
            else None
        ),
        report=report,
    )


def _preflight_manifest(run_path: Path, run_id: str) -> RunManifest:
    content = _read_root_file(
        run_path,
        MANIFEST_FILENAME,
        maximum_bytes=_MAX_HISTORY_MANIFEST_BYTES,
    )
    try:
        manifest = RunManifest.from_bytes(content)
    except (TypeError, ValueError) as exc:
        raise _MalformedBundleError from exc
    if manifest.run_id != run_id:
        raise _ChangedBundleError
    if len(
        manifest.artifacts
    ) != _MAX_HISTORY_ARTIFACTS or not _declares_reciprocal_inventory(manifest):
        raise _UnsupportedBundleError
    if (
        any(
            artifact.size_bytes > _maximum_bytes_for_path(artifact.path)
            for artifact in manifest.artifacts
        )
        or sum(artifact.size_bytes for artifact in manifest.artifacts)
        > _MAX_HISTORY_TOTAL_BYTES
    ):
        raise _MalformedBundleError
    return manifest


def _declares_reciprocal_inventory(manifest: RunManifest) -> bool:
    paths = {artifact.path for artifact in manifest.artifacts}
    if not {
        "run.json",
        "reports/report.json",
        "reports/terminal.txt",
    }.issubset(paths):
        return False
    for directory in _ITEM_DIRECTORY_NAMES:
        directory_paths = tuple(
            path for path in paths if path.startswith(f"{directory}/")
        )
        if len(directory_paths) != _EXPECTED_ITEM_COUNT or any(
            _ITEM_NAME_PATTERN.fullmatch(path.removeprefix(f"{directory}/")) is None
            for path in directory_paths
        ):
            return False
    return len(paths) == _MAX_HISTORY_ARTIFACTS


def _maximum_bytes_for_path(path: str) -> int:
    if path == "run.json":
        return _MAX_RUN_METADATA_BYTES
    if path == "reports/report.json":
        return _MAX_PUBLIC_REPORT_BYTES
    if path == "reports/terminal.txt":
        return _MAX_TERMINAL_REPORT_BYTES
    if any(path.startswith(f"{directory}/") for directory in _ITEM_DIRECTORY_NAMES):
        return _MAX_NORMALIZED_ARTIFACT_BYTES
    raise _UnsupportedBundleError


def _read_root_file(
    run_path: Path,
    name: str,
    *,
    maximum_bytes: int,
) -> bytes:
    try:
        run_fd = open_anchored_directory(run_path)
    except UnsafeEvidencePathError as exc:
        raise _ChangedBundleError from exc
    try:
        try:
            metadata = os.stat(name, dir_fd=run_fd, follow_symlinks=False)
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
            ):
                raise _ChangedBundleError
            if metadata.st_size > maximum_bytes:
                raise _MalformedBundleError
            return read_regular_file_at(
                run_fd,
                name,
                display_path=name,
                maximum_bytes=maximum_bytes,
            )
        except FileNotFoundError:
            raise
        except (UnsafeEvidencePathError, UnstableEvidenceFileError) as exc:
            raise _ChangedBundleError from exc
        except OSError as exc:
            raise _ChangedBundleError from exc
    finally:
        os.close(run_fd)


def _read_report_file(run_path: Path) -> bytes:
    try:
        run_fd = open_anchored_directory(run_path)
    except UnsafeEvidencePathError as exc:
        raise _ChangedBundleError from exc
    reports_fd: int | None = None
    try:
        try:
            reports_fd = open_directory_at(
                run_fd,
                "reports",
                display_path="reports",
            )
            return read_regular_file_at(
                reports_fd,
                "report.json",
                display_path="reports/report.json",
                maximum_bytes=_MAX_PUBLIC_REPORT_BYTES,
            )
        except FileNotFoundError as exc:
            raise _MalformedBundleError from exc
        except (UnsafeEvidencePathError, UnstableEvidenceFileError) as exc:
            raise _ChangedBundleError from exc
        except OSError as exc:
            raise _ChangedBundleError from exc
    finally:
        if reports_fd is not None:
            os.close(reports_fd)
        os.close(run_fd)


def _confirmed_state_record(
    run_path: Path,
    run_id: str,
    manifest: RunManifest,
    manifest_sha256: str,
    state: EvidenceHistoryState,
) -> EvidenceHistoryRecord:
    if _bounded_verification_state(run_path, manifest, manifest_sha256) is not None:
        return _state_record(run_id, EvidenceHistoryState.TAMPERED)
    return _state_record(run_id, state)


def _bounded_verification_state(
    run_path: Path,
    manifest: RunManifest,
    manifest_sha256: str,
) -> EvidenceHistoryState | None:
    """Verify only the exact small reciprocal tree under history limits."""
    try:
        inventory = _scan_actual_inventory(run_path)
        declared = {artifact.path: artifact for artifact in manifest.artifacts}
        if set(inventory.artifact_sizes) != set(declared):
            raise _ChangedBundleError
        if sum(inventory.artifact_sizes.values()) > _MAX_HISTORY_TOTAL_BYTES:
            raise _ChangedBundleError
        current_manifest = _read_root_file(
            run_path,
            MANIFEST_FILENAME,
            maximum_bytes=_MAX_HISTORY_MANIFEST_BYTES,
        )
        if (
            hashlib.sha256(current_manifest).hexdigest() != manifest_sha256
            or current_manifest != manifest.to_bytes()
        ):
            raise _ChangedBundleError
        for path in sorted(declared):
            artifact = declared[path]
            maximum_bytes = _maximum_bytes_for_path(path)
            if (
                inventory.artifact_sizes[path] != artifact.size_bytes
                or artifact.size_bytes > maximum_bytes
            ):
                raise _ChangedBundleError
            scanned = _hash_artifact(run_path, path, maximum_bytes=maximum_bytes)
            if (
                scanned.size_bytes != artifact.size_bytes
                or scanned.sha256 != artifact.sha256
            ):
                raise _ChangedBundleError
    except OSError, UnsafeEvidencePathError, _MalformedBundleError:
        return EvidenceHistoryState.TAMPERED
    return None


def _scan_actual_inventory(run_path: Path) -> _ActualInventory:
    """Inspect the exact tree and actual sizes before hashing any artifact."""
    try:
        run_fd = open_anchored_directory(run_path)
    except UnsafeEvidencePathError as exc:
        raise _ChangedBundleError from exc
    try:
        root_names = _bounded_names(run_fd, maximum=_EXPECTED_ROOT_ENTRY_COUNT)
        if set(root_names) != _ROOT_ENTRY_NAMES:
            raise _ChangedBundleError
        _bounded_regular_size(
            run_fd,
            MANIFEST_FILENAME,
            maximum_bytes=_MAX_HISTORY_MANIFEST_BYTES,
        )
        artifact_sizes = {
            "run.json": _bounded_regular_size(
                run_fd,
                "run.json",
                maximum_bytes=_MAX_RUN_METADATA_BYTES,
            )
        }
        for directory in _ITEM_DIRECTORY_NAMES:
            artifact_sizes.update(_scan_item_directory(run_fd, directory))
        artifact_sizes.update(_scan_report_directory(run_fd))
        if (
            len(artifact_sizes) != _MAX_HISTORY_ARTIFACTS
            or sum(artifact_sizes.values()) > _MAX_HISTORY_TOTAL_BYTES
        ):
            raise _ChangedBundleError
        return _ActualInventory(artifact_sizes=artifact_sizes)
    finally:
        os.close(run_fd)


def _scan_item_directory(run_fd: int, directory: str) -> dict[str, int]:
    child_fd = _open_history_directory(run_fd, directory)
    try:
        names = _bounded_names(child_fd, maximum=_EXPECTED_ITEM_COUNT)
        if len(names) != _EXPECTED_ITEM_COUNT or any(
            _ITEM_NAME_PATTERN.fullmatch(name) is None for name in names
        ):
            raise _ChangedBundleError
        return {
            f"{directory}/{name}": _bounded_regular_size(
                child_fd,
                name,
                maximum_bytes=_MAX_NORMALIZED_ARTIFACT_BYTES,
            )
            for name in names
        }
    finally:
        os.close(child_fd)


def _scan_report_directory(run_fd: int) -> dict[str, int]:
    reports_fd = _open_history_directory(run_fd, "reports")
    try:
        names = _bounded_names(reports_fd, maximum=len(_REPORT_ENTRY_NAMES))
        if set(names) != _REPORT_ENTRY_NAMES:
            raise _ChangedBundleError
        return {
            "reports/report.json": _bounded_regular_size(
                reports_fd,
                "report.json",
                maximum_bytes=_MAX_PUBLIC_REPORT_BYTES,
            ),
            "reports/terminal.txt": _bounded_regular_size(
                reports_fd,
                "terminal.txt",
                maximum_bytes=_MAX_TERMINAL_REPORT_BYTES,
            ),
        }
    finally:
        os.close(reports_fd)


def _open_history_directory(parent_fd: int, name: str) -> int:
    try:
        return open_directory_at(parent_fd, name, display_path=name)
    except UnsafeEvidencePathError as exc:
        raise _ChangedBundleError from exc


def _bounded_names(directory_fd: int, *, maximum: int) -> tuple[str, ...]:
    names: list[str] = []
    try:
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > maximum:
                    break
    except OSError as exc:
        raise _ChangedBundleError from exc
    if len(names) > maximum:
        raise _ChangedBundleError
    return tuple(sorted(names))


def _bounded_regular_size(
    parent_fd: int,
    name: str,
    *,
    maximum_bytes: int,
) -> int:
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise _ChangedBundleError from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > maximum_bytes
    ):
        raise _ChangedBundleError
    return metadata.st_size


def _hash_artifact(
    run_path: Path,
    path: str,
    *,
    maximum_bytes: int,
) -> ScannedFile:
    try:
        run_fd = open_anchored_directory(run_path)
    except UnsafeEvidencePathError as exc:
        raise _ChangedBundleError from exc
    parent_fd = os.dup(run_fd)
    os.close(run_fd)
    components = path.split("/")
    try:
        for component in components[:-1]:
            child_fd = _open_history_directory(parent_fd, component)
            os.close(parent_fd)
            parent_fd = child_fd
        return hash_file_at(
            parent_fd,
            components[-1],
            display_path=path,
            maximum_bytes=maximum_bytes,
        )
    finally:
        os.close(parent_fd)


def _state_record(
    run_id: str,
    state: EvidenceHistoryState,
) -> EvidenceHistoryRecord:
    return EvidenceHistoryRecord(
        run_id=run_id,
        state=state,
        issues=_STATE_ISSUES[state],
    )


def _manifest_sha256(manifest: RunManifest) -> str:
    return hashlib.sha256(manifest.to_bytes()).hexdigest()


def _require_manifest_bytes(
    manifest: RunManifest,
    path: str,
    content: bytes,
) -> None:
    artifact = next(
        (item for item in manifest.artifacts if item.path == path),
        None,
    )
    if (
        artifact is None
        or len(content) != artifact.size_bytes
        or hashlib.sha256(content).hexdigest() != artifact.sha256
    ):
        raise _ChangedBundleError


def _load_json_object(content: bytes) -> dict[str, object]:
    try:
        decoded = content.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(value, dict):
            raise _MalformedBundleError
        canonical = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise _MalformedBundleError from exc
    if canonical != content:
        raise _MalformedBundleError
    return cast("dict[str, object]", value)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _MalformedBundleError
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    del value
    raise _MalformedBundleError


def _parse_run_metadata(
    value: dict[str, object],
    directory_run_id: str,
) -> _RunMetadata:
    if value.get("bundle_kind") != AWS_RECIPROCAL_BUNDLE_KIND:
        raise _UnsupportedBundleError
    if value.get("evidence_schema_version") != AWS_RECIPROCAL_EVIDENCE_SCHEMA_VERSION:
        raise _UnsupportedBundleError
    if set(value) != _RUN_FIELDS:
        raise _MalformedBundleError
    run_id = _identifier(value["run_id"])
    scenario_id = _identifier(value["scenario_id"])
    if run_id != directory_run_id:
        raise _ChangedBundleError
    aggregate_status = _assertion_status(value["aggregate_status"])
    if aggregate_status not in _SUPPORTED_ASSERTION_STATUSES:
        raise _MalformedBundleError
    action_ids = _identifier_pair(value["action_ids"])
    probe_ids = _identifier_pair(value["probe_ids"])
    assertion_ids = _identifier_pair(value["assertion_ids"])
    target_environment = value["target_environment"]
    target_region = value["target_region"]
    target_pseudonym = value["target_pseudonym_sha256"]
    if (
        type(target_environment) is not str
        or target_environment not in _SUPPORTED_ENVIRONMENTS
        or type(target_region) is not str
        or _AWS_REGION_PATTERN.fullmatch(target_region) is None
        or type(target_pseudonym) is not str
        or _SHA256_PATTERN.fullmatch(target_pseudonym) is None
    ):
        raise _MalformedBundleError
    return _RunMetadata(
        run_id=run_id,
        scenario_id=scenario_id,
        aggregate_status=aggregate_status,
        target_region=target_region,
        action_ids=action_ids,
        probe_ids=probe_ids,
        assertion_ids=assertion_ids,
    )


def _validate_manifest_contract(
    manifest: RunManifest,
    metadata: _RunMetadata,
) -> None:
    expected: dict[str, tuple[str, Sensitivity, int]] = {
        "run.json": (
            "application/json",
            Sensitivity.INTERNAL,
            _MAX_RUN_METADATA_BYTES,
        ),
        "reports/report.json": (
            "application/json",
            Sensitivity.PUBLIC,
            _MAX_PUBLIC_REPORT_BYTES,
        ),
        "reports/terminal.txt": (
            "text/plain",
            Sensitivity.PUBLIC,
            _MAX_TERMINAL_REPORT_BYTES,
        ),
    }
    for directory, identifiers, sensitivity in (
        ("actions", metadata.action_ids, Sensitivity.INTERNAL),
        ("probes", metadata.probe_ids, Sensitivity.INTERNAL),
        ("results", metadata.assertion_ids, Sensitivity.PUBLIC),
    ):
        for identifier in identifiers:
            path = _item_path(directory, identifier)
            if path in expected:
                raise _MalformedBundleError
            expected[path] = (
                "application/json",
                sensitivity,
                _MAX_NORMALIZED_ARTIFACT_BYTES,
            )
    artifacts = {artifact.path: artifact for artifact in manifest.artifacts}
    if set(artifacts) != set(expected):
        raise _MalformedBundleError
    for path, (media_type, sensitivity, maximum_bytes) in expected.items():
        artifact = artifacts[path]
        if (
            artifact.media_type != media_type
            or artifact.sensitivity is not sensitivity
            or artifact.size_bytes > maximum_bytes
        ):
            raise _MalformedBundleError


def _item_path(directory: str, identifier: str) -> str:
    digest = hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:16]
    return f"{directory}/item-{digest}.json"


def _parse_public_report(
    value: dict[str, object],
    metadata: _RunMetadata,
) -> EvidenceHistoryReport:
    if value.get("schema_version") != "1":
        raise _UnsupportedBundleError
    if set(value) != _REPORT_FIELDS or value["run_id"] != metadata.run_id:
        raise _MalformedBundleError
    aggregate_status = _assertion_status(value["aggregate_status"])
    raw_results = value["results"]
    if not isinstance(raw_results, list) or len(raw_results) != _PAIR_SIZE:
        raise _MalformedBundleError
    summaries = tuple(_parse_report_result(item) for item in raw_results)
    result_ids = tuple(summary.assertion_id for summary in summaries)
    if result_ids != tuple(sorted(result_ids)) or result_ids != metadata.assertion_ids:
        raise _MalformedBundleError
    statuses = tuple(summary.status for summary in summaries)
    calculated_status = aggregate_statuses(statuses)
    exit_code = value["exit_code"]
    if (
        aggregate_status is not metadata.aggregate_status
        or aggregate_status is not calculated_status
        or type(exit_code) is not int
        or exit_code != int(exit_code_for_status(aggregate_status))
    ):
        raise _MalformedBundleError
    return EvidenceHistoryReport(
        results=tuple(
            EvidenceHistoryResultSummary(
                assertion_id=f"direction-{index:02d}",
                status=summary.status,
            )
            for index, summary in enumerate(summaries, start=1)
        )
    )


def _parse_report_result(value: object) -> _ParsedResult:
    if not isinstance(value, dict) or set(value) != _RESULT_FIELDS:
        raise _MalformedBundleError
    assertion_id = _identifier(value["assertion_id"])
    status = _assertion_status(value["status"])
    if (
        status not in _SUPPORTED_ASSERTION_STATUSES
        or value["assertion_type"] != AssertionType.EVIDENCE_BACKED.value
        or value["schema_version"] != ASSERTION_RESULT_SCHEMA_VERSION
        or value["evaluator_version"] != RETRIEVAL_BOUNDARY_EVALUATOR_VERSION
    ):
        raise _MalformedBundleError
    started_at = _timestamp(value["evaluation_started_at"])
    completed_at = _timestamp(value["evaluation_completed_at"])
    if completed_at != started_at:
        raise _MalformedBundleError
    _validate_evidence_ids(value["evidence_ids"])
    _validate_expected(value["expected"])
    _validate_observed(value["observed"])
    if value["limitations"] != sorted(RETRIEVAL_BOUNDARY_FIXED_LIMITATIONS):
        raise _MalformedBundleError
    status_reason = value["status_reason"]
    if (
        type(status_reason) is not str
        or not status_reason.strip()
        or len(status_reason) > _MAX_STATUS_REASON_LENGTH
    ):
        raise _MalformedBundleError
    return _ParsedResult(
        assertion_id=assertion_id,
        status=status,
    )


def _validate_evidence_ids(value: object) -> None:
    if (
        not isinstance(value, list)
        or len(value) > _MAX_EVIDENCE_IDS
        or any(
            type(item) is not str
            or len(item) > _MAX_IDENTIFIER_LENGTH
            or _IDENTIFIER_PATTERN.fullmatch(item) is None
            for item in value
        )
    ):
        raise _MalformedBundleError
    identifiers = cast("list[str]", value)
    if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
        raise _MalformedBundleError


def _validate_expected(value: object) -> None:
    if not isinstance(value, dict) or set(value) != _EXPECTED_FIELDS:
        raise _MalformedBundleError
    if any(type(item) is not bool for item in value.values()):
        raise _MalformedBundleError
    if value != _EXPECTED_VALUES:
        raise _MalformedBundleError


def _validate_observed(value: object) -> None:
    if not isinstance(value, dict) or set(value) != _OBSERVED_FIELDS:
        raise _MalformedBundleError
    for field_name in _NULLABLE_OBSERVED_BOOLEANS:
        item = value[field_name]
        if item is not None and type(item) is not bool:
            raise _MalformedBundleError
    if type(value["retrieval_path_exercised"]) is not bool:
        raise _MalformedBundleError
    retrieved_item_count = value["retrieved_item_count"]
    if retrieved_item_count is not None and (
        type(retrieved_item_count) is not int
        or not 0 <= retrieved_item_count <= _MAX_RETRIEVED_ITEMS
    ):
        raise _MalformedBundleError
    normalized_state = value["normalized_evidence_state"]
    if (
        type(normalized_state) is not str
        or len(normalized_state) > _MAX_NORMALIZED_STATE_LENGTH
        or _NORMALIZED_STATE_PATTERN.fullmatch(normalized_state) is None
    ):
        raise _MalformedBundleError


def _identifier(value: object) -> str:
    if (
        type(value) is not str
        or len(value) > _MAX_IDENTIFIER_LENGTH
        or _IDENTIFIER_PATTERN.fullmatch(value) is None
    ):
        raise _MalformedBundleError
    return value


def _identifier_pair(value: object) -> tuple[str, str]:
    if not isinstance(value, list) or len(value) != _PAIR_SIZE:
        raise _MalformedBundleError
    identifiers = tuple(_identifier(item) for item in value)
    if identifiers != tuple(sorted(identifiers)) or len(set(identifiers)) != _PAIR_SIZE:
        raise _MalformedBundleError
    return cast("tuple[str, str]", identifiers)


def _assertion_status(value: object) -> AssertionStatus:
    if type(value) is not str:
        raise _MalformedBundleError
    try:
        return AssertionStatus(value)
    except ValueError as exc:
        raise _MalformedBundleError from exc


def _timestamp(value: object) -> datetime:
    if type(value) is not str or len(value) != _UTC_MICROSECOND_TIMESTAMP_LENGTH:
        raise _MalformedBundleError
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise _MalformedBundleError from exc


def _caused_by_file_not_found(error: BaseException) -> bool:
    current: BaseException | None = error
    while current is not None:
        if isinstance(current, FileNotFoundError):
            return True
        current = current.__cause__
    return False
