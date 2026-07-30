"""Tests for bounded, redacted reciprocal evidence history."""

# ruff: noqa: D103, S105

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

import pytest

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
    aggregate_statuses,
    exit_code_for_status,
)
from cai_verify.evidence import RunDirectory, Sensitivity
from cai_verify.evidence._filesystem import read_regular_file_at
from cai_verify.ui import history as history_module
from cai_verify.ui.history import (
    EVIDENCE_HISTORY_SCHEMA_VERSION,
    MAX_EVIDENCE_HISTORY_PAGE_SIZE,
    EvidenceHistoryLimitError,
    EvidenceHistoryRecord,
    EvidenceHistoryRunNotFoundError,
    EvidenceHistoryState,
    InvalidEvidenceHistoryRequestError,
    UnsafeEvidenceHistoryError,
    get_evidence_history_record,
    list_evidence_history,
    verify_generated_evidence_run,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

_ACTION_IDS = ("action-a", "action-b")
_PROBE_IDS = ("probe-a", "probe-b")
_ASSERTION_IDS = ("assertion-a", "assertion-b")
_TIMESTAMP = "2026-07-30T12:00:00.000000Z"
_SAFE_UI_RUN_ID = "ui-20260730T120000000000Z-0123456789abcdef0123456789abcdef"
_EXPECTED = {
    "baseline_canary_observed": True,
    "boundary_canary_observed": False,
    "complete_context_scan_succeeded": True,
    "exactly_one_correlated_retrieval_record": True,
    "pre_generation_phase_matched": True,
    "retrieval_path_exercised": True,
    "retrieval_succeeded": True,
    "undeclared_synthetic_marker_observed": False,
}
_OBSERVED = {
    "baseline_canary_observed": True,
    "boundary_canary_observed": False,
    "normalized_evidence_state": "complete",
    "retrieval_path_exercised": True,
    "retrieved_item_count": 1,
    "undeclared_synthetic_marker_observed": False,
}
_SECRET_VALUES = (
    "AKIAIOSFODNN7EXAMPLE",
    "synthetic-correlation-secret",
    "111122223333",
    "arn:aws:iam::111122223333:role/private-reader",
    "botocore exception diagnostic",
)


def test_verified_reciprocal_history_returns_only_safe_fixed_fields(
    tmp_path: Path,
) -> None:
    root = tmp_path / "runs"
    run_path = _create_reciprocal_bundle(root, _SAFE_UI_RUN_ID)

    listed = list_evidence_history(root).items[0]
    record = get_evidence_history_record(root, listed.run_id)

    assert record.state is EvidenceHistoryState.VERIFIED
    assert record.run_id == listed.run_id
    assert record.run_id == _SAFE_UI_RUN_ID
    assert record.aggregate_status is AssertionStatus.PASS
    assert record.scenario_id == "scenario-01"
    assert record.target_region == "eu-west-2"
    assert record.evidence_path == str(run_path.absolute())
    assert record.issues == ()
    assert record.report is not None
    assert [
        (result.assertion_id, result.status) for result in record.report.results
    ] == [
        ("direction-01", AssertionStatus.PASS),
        ("direction-02", AssertionStatus.PASS),
    ]
    wire = record.to_dict()
    assert set(wire) == {
        "aggregateStatus",
        "evidencePath",
        "issues",
        "report",
        "runId",
        "scenarioId",
        "state",
        "targetRegion",
    }
    assert wire["evidencePath"] == str(run_path.absolute())


def test_generated_run_helper_requires_strict_safe_id_and_returns_verified_path(
    tmp_path: Path,
) -> None:
    root = tmp_path / "runs"
    run_path = _create_reciprocal_bundle(root, _SAFE_UI_RUN_ID)

    record = verify_generated_evidence_run(root, _SAFE_UI_RUN_ID)

    assert record.state is EvidenceHistoryState.VERIFIED
    assert record.evidence_path == str(run_path.absolute())
    assert record.run_id == _SAFE_UI_RUN_ID
    assert _SAFE_UI_RUN_ID not in repr(record)
    with pytest.raises(InvalidEvidenceHistoryRequestError):
        verify_generated_evidence_run(root, "run-operator-authored")


def test_generated_run_verification_ignores_unrelated_unsafe_root_entry(
    tmp_path: Path,
) -> None:
    root = tmp_path / "runs"
    _create_reciprocal_bundle(root, _SAFE_UI_RUN_ID)
    (root / "unsafe-link").symlink_to(tmp_path)

    record = verify_generated_evidence_run(root, _SAFE_UI_RUN_ID)

    assert record.state is EvidenceHistoryState.VERIFIED
    with pytest.raises(UnsafeEvidenceHistoryError):
        list_evidence_history(root)


def test_generated_run_verification_ignores_history_root_count_limit(
    tmp_path: Path,
) -> None:
    root = tmp_path / "runs"
    _create_reciprocal_bundle(root, _SAFE_UI_RUN_ID)
    for index in range(1_001):
        (root / f"unrelated-{index:04d}").mkdir()

    record = verify_generated_evidence_run(root, _SAFE_UI_RUN_ID)

    assert record.state is EvidenceHistoryState.VERIFIED
    with pytest.raises(EvidenceHistoryLimitError):
        list_evidence_history(root)


def test_page_order_cursor_and_wire_shape_are_deterministic(tmp_path: Path) -> None:
    root = tmp_path / "runs"
    for index in range(55):
        (root / f"run-{index:03d}").mkdir(parents=True)

    first = list_evidence_history(root, limit=MAX_EVIDENCE_HISTORY_PAGE_SIZE)
    second = list_evidence_history(root, cursor=first.next_cursor)

    assert [item.run_id for item in first.items] == [
        history_module._opaque_run_id(f"run-{index:03d}")  # noqa: SLF001
        for index in range(54, 4, -1)
    ]
    assert first.next_cursor == history_module._opaque_run_id(  # noqa: SLF001
        "run-005"
    )
    assert [item.run_id for item in second.items] == [
        history_module._opaque_run_id(f"run-{index:03d}")  # noqa: SLF001
        for index in range(4, -1, -1)
    ]
    assert second.next_cursor is None
    assert all(
        item.state is EvidenceHistoryState.UNFINALIZED
        for item in (*first.items, *second.items)
    )
    assert set(first.to_dict()) == {"items", "nextCursor", "schemaVersion"}
    assert first.to_dict()["schemaVersion"] == EVIDENCE_HISTORY_SCHEMA_VERSION
    assert first.to_dict() == list_evidence_history(root).to_dict()


def test_probe_of_empty_or_missing_root_is_empty(tmp_path: Path) -> None:
    missing = tmp_path / "not-created"

    page = list_evidence_history(missing)

    assert page.items == ()
    assert page.next_cursor is None


@pytest.mark.parametrize("limit", [0, 51, True, "2"])
def test_invalid_page_limits_fail_with_fixed_error(
    tmp_path: Path,
    limit: object,
) -> None:
    with pytest.raises(
        InvalidEvidenceHistoryRequestError,
        match=r"\Ainvalid evidence history request\Z",
    ):
        list_evidence_history(tmp_path, limit=limit)  # type: ignore[arg-type]


def test_unknown_and_invalid_cursors_fail_without_echoing_values(
    tmp_path: Path,
) -> None:
    root = tmp_path / "runs"
    (root / "run-001").mkdir(parents=True)

    for cursor in ("missing-secret-cursor", "run-" + ("0" * 32), "../escape"):
        with pytest.raises(InvalidEvidenceHistoryRequestError) as caught:
            list_evidence_history(root, cursor=cursor)
        assert cursor not in str(caught.value)


def test_missing_selected_run_has_fixed_non_echoing_error(tmp_path: Path) -> None:
    root = tmp_path / "runs"
    root.mkdir()
    opaque_missing = "run-" + ("f" * 32)

    with pytest.raises(EvidenceHistoryRunNotFoundError) as caught:
        get_evidence_history_record(root, opaque_missing)

    assert opaque_missing not in str(caught.value)


def test_more_than_one_thousand_entries_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "runs"
    root.mkdir()
    for index in range(1_001):
        (root / f"run-{index:04d}").mkdir()

    with pytest.raises(
        EvidenceHistoryLimitError,
        match=r"\Aevidence history exceeds the supported run limit\Z",
    ):
        list_evidence_history(root)


@pytest.mark.parametrize("unsafe_kind", ["symlink", "file", "invalid-name"])
def test_unsafe_root_entries_are_rejected_without_exposing_names(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    root = tmp_path / "runs"
    root.mkdir()
    secret_name = "run-private"
    if unsafe_kind == "symlink":
        target = tmp_path / "target"
        target.mkdir()
        (root / secret_name).symlink_to(target, target_is_directory=True)
    elif unsafe_kind == "file":
        (root / secret_name).write_bytes(b"not a run")
    else:
        secret_name = ".private-entry"
        (root / secret_name).mkdir()

    with pytest.raises(UnsafeEvidenceHistoryError) as caught:
        list_evidence_history(root)

    assert secret_name not in str(caught.value)


def test_unfinalized_run_is_never_reported_complete(tmp_path: Path) -> None:
    root = tmp_path / "runs"
    run = RunDirectory.create(root, "run-unfinalized")
    run.write_evidence(
        "partial.json",
        b"{}",
        media_type="application/json",
        sensitivity=Sensitivity.INTERNAL,
    )
    run.close()

    record = _get_record_for_raw(root, "run-unfinalized")

    assert record.state is EvidenceHistoryState.UNFINALIZED
    _assert_suppressed(record.to_dict(), issue="missing_manifest")


def test_malformed_manifest_is_classified_without_exception_details(
    tmp_path: Path,
) -> None:
    root = tmp_path / "runs"
    run_path = root / "run-bad-manifest"
    run_path.mkdir(parents=True)
    (run_path / "manifest.json").write_bytes(b'{"private":"SDK detail"}')

    record = _get_record_for_raw(root, "run-bad-manifest")

    assert record.state is EvidenceHistoryState.MALFORMED
    _assert_suppressed(record.to_dict(), issue="malformed_bundle")


@pytest.mark.parametrize(
    ("run_content", "report_content"),
    [
        (
            b'{"bundle_kind":"aws-reciprocal-retrieval-boundary",'
            b'"bundle_kind":"private"}',
            None,
        ),
        (None, b'{"schema_version":"1","schema_version":"private"}'),
        (b"not-json", None),
        (None, b"not-json"),
    ],
)
def test_malformed_or_duplicate_json_is_classified(
    tmp_path: Path,
    run_content: bytes | None,
    report_content: bytes | None,
) -> None:
    root = tmp_path / "runs"
    _create_reciprocal_bundle(
        root,
        "run-malformed",
        run_content=run_content,
        report_content=report_content,
    )

    record = _get_record_for_raw(root, "run-malformed")

    assert record.state is EvidenceHistoryState.MALFORMED
    _assert_suppressed(record.to_dict(), issue="malformed_bundle")


def test_mixed_type_evidence_ids_are_classified_as_malformed(
    tmp_path: Path,
) -> None:
    root = tmp_path / "runs"
    _create_reciprocal_bundle(
        root,
        "run-mixed-evidence-ids",
        result_updates={"evidence_ids": ["safe-id", 1]},
    )

    record = _get_record_for_raw(root, "run-mixed-evidence-ids")

    assert record.state is EvidenceHistoryState.MALFORMED
    _assert_suppressed(record.to_dict(), issue="malformed_bundle")


def test_report_read_os_error_is_classified_as_tampered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "runs"
    _create_reciprocal_bundle(root, "run-report-read-error")
    original_read = read_regular_file_at

    def fail_report_read(
        parent_fd: int,
        name: str,
        *,
        display_path: str,
        maximum_bytes: int,
    ) -> bytes:
        if display_path == "reports/report.json":
            message = "private filesystem diagnostic"
            raise OSError(message)
        return original_read(
            parent_fd,
            name,
            display_path=display_path,
            maximum_bytes=maximum_bytes,
        )

    monkeypatch.setattr(history_module, "read_regular_file_at", fail_report_read)

    record = _get_record_for_raw(root, "run-report-read-error")

    assert record.state is EvidenceHistoryState.TAMPERED
    _assert_suppressed(record.to_dict(), issue="integrity_failed")


def test_canonicalization_recursion_is_classified_as_malformed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_canonicalization(*args: object, **kwargs: object) -> str:
        del args, kwargs
        message = "private recursion diagnostic"
        raise RecursionError(message)

    monkeypatch.setattr(json, "dumps", fail_canonicalization)

    with pytest.raises(history_module._MalformedBundleError):  # noqa: SLF001
        history_module._load_json_object(b"{}")  # noqa: SLF001


@pytest.mark.parametrize(
    ("run_updates", "report_updates"),
    [
        ({"bundle_kind": "another-bundle"}, None),
        ({"evidence_schema_version": "2"}, None),
        (None, {"schema_version": "2"}),
    ],
)
def test_unsupported_kind_or_version_is_classified(
    tmp_path: Path,
    run_updates: Mapping[str, object] | None,
    report_updates: Mapping[str, object] | None,
) -> None:
    root = tmp_path / "runs"
    _create_reciprocal_bundle(
        root,
        "run-unsupported",
        run_updates=run_updates,
        report_updates=report_updates,
    )

    record = _get_record_for_raw(root, "run-unsupported")

    assert record.state is EvidenceHistoryState.UNSUPPORTED
    _assert_suppressed(record.to_dict(), issue="unsupported_bundle")


@pytest.mark.parametrize(
    ("run_updates", "report_updates"),
    [
        ({"aggregate_status": "FAIL"}, None),
        ({"target_region": "us-east-1"}, {"aggregate_status": "FAIL"}),
        ({"assertion_ids": ["assertion-a", "assertion-c"]}, None),
        (None, {"exit_code": 3}),
        (None, {"run_id": "another-run"}),
        (None, {"results": []}),
    ],
)
def test_conflicting_fixed_bundle_fields_are_malformed(
    tmp_path: Path,
    run_updates: Mapping[str, object] | None,
    report_updates: Mapping[str, object] | None,
) -> None:
    root = tmp_path / "runs"
    _create_reciprocal_bundle(
        root,
        "run-conflict",
        run_updates=run_updates,
        report_updates=report_updates,
    )

    record = _get_record_for_raw(root, "run-conflict")

    assert record.state is EvidenceHistoryState.MALFORMED
    _assert_suppressed(record.to_dict(), issue="malformed_bundle")


def test_oversized_run_metadata_is_malformed_without_parsing(tmp_path: Path) -> None:
    root = tmp_path / "runs"
    oversized = b'{"padding":"' + (b"x" * (16 * 1024)) + b'"}'
    _create_reciprocal_bundle(
        root,
        "run-oversized",
        run_content=oversized,
    )

    record = _get_record_for_raw(root, "run-oversized")

    assert record.state is EvidenceHistoryState.MALFORMED
    _assert_suppressed(record.to_dict(), issue="malformed_bundle")


def test_digest_or_size_change_is_tampered_and_suppresses_parsed_fields(
    tmp_path: Path,
) -> None:
    root = tmp_path / "runs"
    run_path = _create_reciprocal_bundle(root, "run-tampered")
    report_path = run_path / "reports" / "report.json"
    report_path.write_bytes(report_path.read_bytes() + b" ")

    record = _get_record_for_raw(root, "run-tampered")

    assert record.state is EvidenceHistoryState.TAMPERED
    _assert_suppressed(record.to_dict(), issue="integrity_failed")


def test_unsafe_artifact_in_finalized_run_is_tampered(tmp_path: Path) -> None:
    root = tmp_path / "runs"
    run_path = _create_reciprocal_bundle(root, "run-unsafe-artifact")
    action_path = run_path / _item_path("actions", _ACTION_IDS[0])
    action_path.unlink()
    action_path.symlink_to(tmp_path / "outside")

    record = _get_record_for_raw(root, "run-unsafe-artifact")

    assert record.state is EvidenceHistoryState.TAMPERED
    _assert_suppressed(record.to_dict(), issue="integrity_failed")


@pytest.mark.parametrize("attack", ["unexpected", "declared-file"])
def test_actual_oversized_files_are_rejected_before_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
) -> None:
    root = tmp_path / "runs"
    raw_run_id = f"run-large-{attack}"
    run_path = _create_reciprocal_bundle(root, raw_run_id)
    if attack == "unexpected":
        attacked_path = run_path / "unexpected.bin"
    else:
        attacked_path = run_path / _item_path("actions", _ACTION_IDS[0])
    attacked_path.write_bytes(b"x" * (2 * 1024 * 1024))

    def fail_hash(*args: object, **kwargs: object) -> object:
        del args, kwargs
        message = "oversized content reached the hashing stage"
        raise AssertionError(message)

    monkeypatch.setattr(history_module, "hash_file_at", fail_hash)

    record = _get_record_for_raw(root, raw_run_id)

    assert record.state is EvidenceHistoryState.TAMPERED
    _assert_suppressed(record.to_dict(), issue="integrity_failed")


def test_swap_read_restore_run_bytes_cannot_bypass_manifest_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "runs"
    raw_run_id = "run-swap-restore"
    run_path = _create_reciprocal_bundle(root, raw_run_id)
    run_file = run_path / "run.json"
    original_content = run_file.read_bytes()
    swapped_content = original_content.replace(b"sandbox", b"staging")
    assert len(swapped_content) == len(original_content)
    original_read = history_module._read_root_file  # noqa: SLF001
    swapped = False

    def swapping_read(
        selected_run_path: Path,
        name: str,
        *,
        maximum_bytes: int,
    ) -> bytes:
        nonlocal swapped
        if name == "run.json" and not swapped:
            swapped = True
            run_file.write_bytes(swapped_content)
            try:
                return original_read(
                    selected_run_path,
                    name,
                    maximum_bytes=maximum_bytes,
                )
            finally:
                run_file.write_bytes(original_content)
        return original_read(
            selected_run_path,
            name,
            maximum_bytes=maximum_bytes,
        )

    monkeypatch.setattr(history_module, "_read_root_file", swapping_read)

    record = _get_record_for_raw(root, raw_run_id)

    assert swapped
    assert record.state is EvidenceHistoryState.TAMPERED
    _assert_suppressed(record.to_dict(), issue="integrity_failed")


def test_exact_report_bytes_must_match_verified_manifest_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "runs"
    raw_run_id = "run-report-digest"
    run_path = _create_reciprocal_bundle(root, raw_run_id)
    original_read = history_module._read_report_file  # noqa: SLF001

    def mismatched_read(selected_run_path: Path) -> bytes:
        content = original_read(selected_run_path)
        mismatched = content.replace(b'"PASS"', b'"FAIL"', 1)
        assert len(mismatched) == len(content)
        return mismatched

    monkeypatch.setattr(history_module, "_read_report_file", mismatched_read)

    record = _get_record_for_raw(root, raw_run_id)

    assert run_path.exists()
    assert record.state is EvidenceHistoryState.TAMPERED
    _assert_suppressed(record.to_dict(), issue="integrity_failed")


def test_final_confirmation_detects_change_after_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "runs"
    raw_run_id = "run-post-parse-change"
    run_path = _create_reciprocal_bundle(root, raw_run_id)
    action_path = run_path / _item_path("actions", _ACTION_IDS[0])
    original_read = history_module._read_report_file  # noqa: SLF001
    changed = False

    def read_then_change(selected_run_path: Path) -> bytes:
        nonlocal changed
        content = original_read(selected_run_path)
        action_path.write_bytes(b'{"changed":true}')
        changed = True
        return content

    monkeypatch.setattr(history_module, "_read_report_file", read_then_change)

    record = _get_record_for_raw(root, raw_run_id)

    assert changed
    assert record.state is EvidenceHistoryState.TAMPERED
    _assert_suppressed(record.to_dict(), issue="integrity_failed")


def test_raw_internal_artifacts_and_sensitive_values_never_enter_history(
    tmp_path: Path,
) -> None:
    root = tmp_path / "runs"
    raw_private = _canonical_bytes({"private": list(_SECRET_VALUES)})
    _create_reciprocal_bundle(
        root,
        "run-redacted",
        normalized_artifact_content=raw_private,
    )

    record = _get_record_for_raw(root, "run-redacted")
    serialized = json.dumps(record.to_dict(), sort_keys=True)
    representation = repr(record)

    assert record.state is EvidenceHistoryState.VERIFIED
    assert record.evidence_path is None
    for secret in (
        *_SECRET_VALUES,
        "run-redacted",
        "reciprocal-scenario",
        *_ACTION_IDS,
        *_PROBE_IDS,
        *_ASSERTION_IDS,
    ):
        assert secret not in serialized
        assert secret not in representation


def test_mixed_statuses_are_sorted_and_aggregated_exactly(tmp_path: Path) -> None:
    root = tmp_path / "runs"
    _create_reciprocal_bundle(
        root,
        "run-fail",
        statuses=(AssertionStatus.INCONCLUSIVE, AssertionStatus.FAIL),
    )

    record = _get_record_for_raw(root, "run-fail")

    assert record.aggregate_status is AssertionStatus.FAIL
    assert record.report is not None
    assert [item.status for item in record.report.results] == [
        AssertionStatus.INCONCLUSIVE,
        AssertionStatus.FAIL,
    ]


def _create_reciprocal_bundle(  # noqa: PLR0913 - explicit test corruption knobs.
    root: Path,
    run_id: str,
    *,
    statuses: tuple[AssertionStatus, AssertionStatus] = (
        AssertionStatus.PASS,
        AssertionStatus.PASS,
    ),
    run_updates: Mapping[str, object] | None = None,
    report_updates: Mapping[str, object] | None = None,
    result_updates: Mapping[str, object] | None = None,
    run_content: bytes | None = None,
    report_content: bytes | None = None,
    normalized_artifact_content: bytes = b"{}",
) -> Path:
    aggregate = aggregate_statuses(statuses)
    run_value: dict[str, object] = {
        "action_ids": list(_ACTION_IDS),
        "aggregate_status": aggregate.value,
        "assertion_ids": list(_ASSERTION_IDS),
        "bundle_kind": AWS_RECIPROCAL_BUNDLE_KIND,
        "evidence_schema_version": AWS_RECIPROCAL_EVIDENCE_SCHEMA_VERSION,
        "probe_ids": list(_PROBE_IDS),
        "run_id": run_id,
        "scenario_id": "reciprocal-scenario",
        "target_environment": "sandbox",
        "target_pseudonym_sha256": "0" * 64,
        "target_region": "eu-west-2",
    }
    if run_updates is not None:
        run_value.update(run_updates)
    result_values = [
        _result_value(
            assertion_id=assertion_id,
            action_id=action_id,
            probe_id=probe_id,
            status=status,
        )
        for assertion_id, action_id, probe_id, status in zip(
            _ASSERTION_IDS,
            _ACTION_IDS,
            _PROBE_IDS,
            statuses,
            strict=True,
        )
    ]
    if result_updates is not None:
        result_values[0].update(result_updates)
    report_value: dict[str, object] = {
        "aggregate_status": aggregate.value,
        "exit_code": int(exit_code_for_status(aggregate)),
        "results": result_values,
        "run_id": run_id,
        "schema_version": "1",
    }
    if report_updates is not None:
        report_value.update(report_updates)
    run_bytes = run_content if run_content is not None else _canonical_bytes(run_value)
    report_bytes = (
        report_content if report_content is not None else _canonical_bytes(report_value)
    )

    with RunDirectory.create(root, run_id) as run:
        run.write_evidence(
            "run.json",
            run_bytes,
            media_type="application/json",
            sensitivity=Sensitivity.INTERNAL,
        )
        for directory, identifiers, sensitivity in (
            ("actions", _ACTION_IDS, Sensitivity.INTERNAL),
            ("probes", _PROBE_IDS, Sensitivity.INTERNAL),
        ):
            for identifier in identifiers:
                run.write_evidence(
                    _item_path(directory, identifier),
                    normalized_artifact_content,
                    media_type="application/json",
                    sensitivity=sensitivity,
                )
        for result_value, assertion_id in zip(
            result_values,
            _ASSERTION_IDS,
            strict=True,
        ):
            run.write_evidence(
                _item_path("results", assertion_id),
                _canonical_bytes(result_value),
                media_type="application/json",
                sensitivity=Sensitivity.PUBLIC,
            )
        run.write_evidence(
            "reports/report.json",
            report_bytes,
            media_type="application/json",
            sensitivity=Sensitivity.PUBLIC,
        )
        run.write_evidence(
            "reports/terminal.txt",
            b"synthetic terminal report\n",
            media_type="text/plain",
            sensitivity=Sensitivity.PUBLIC,
        )
        run.finalize_manifest()
        return run.path


def _result_value(
    *,
    assertion_id: str,
    action_id: str,
    probe_id: str,
    status: AssertionStatus,
) -> dict[str, object]:
    return {
        "assertion_id": assertion_id,
        "assertion_type": AssertionType.EVIDENCE_BACKED.value,
        "evaluation_completed_at": _TIMESTAMP,
        "evaluation_started_at": _TIMESTAMP,
        "evaluator_version": RETRIEVAL_BOUNDARY_EVALUATOR_VERSION,
        "evidence_ids": sorted((f"action.{action_id}", f"{probe_id}.retrieval-canary")),
        "expected": _EXPECTED,
        "limitations": sorted(RETRIEVAL_BOUNDARY_FIXED_LIMITATIONS),
        "observed": _OBSERVED,
        "schema_version": ASSERTION_RESULT_SCHEMA_VERSION,
        "status": status.value,
        "status_reason": "Synthetic deterministic result.",
    }


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _item_path(directory: str, identifier: str) -> str:
    digest = hashlib.sha256(identifier.encode()).hexdigest()[:16]
    return f"{directory}/item-{digest}.json"


def _get_record_for_raw(root: Path, raw_run_id: str) -> EvidenceHistoryRecord:
    opaque_run_id = history_module._opaque_run_id(raw_run_id)  # noqa: SLF001
    return get_evidence_history_record(root, opaque_run_id)


def _assert_suppressed(value: Mapping[str, object], *, issue: str) -> None:
    assert value["issues"] == [issue]
    assert value["aggregateStatus"] is None
    assert value["scenarioId"] is None
    assert value["targetRegion"] is None
    assert value["evidencePath"] is None
    assert value["report"] is None
