"""Tests for secure evidence-run storage and offline verification."""

from __future__ import annotations

import hashlib
import json
import os
from typing import TYPE_CHECKING

import pytest

from cai_verify.evidence import (
    MANIFEST_FILENAME,
    EvidenceAlreadyExistsError,
    IncompleteRunError,
    IntegrityIssueCode,
    RunAlreadyExistsError,
    RunFinalizedError,
    Sensitivity,
    UnsafeEvidencePathError,
    create_run_directory,
    verify_run_integrity,
)
from cai_verify.evidence.models import MAX_ARTIFACT_BYTES

if TYPE_CHECKING:
    from pathlib import Path

_EXPECTED_ARTIFACT_COUNT = 2


def test_finalized_run_hashes_exact_bytes_and_verifies_offline(tmp_path: Path) -> None:
    """Manifest digests cover exact stored bytes and metadata survives finalization."""
    runs_root = tmp_path / "runs"
    json_bytes = b'{"synthetic":true}\n'
    text_bytes = b"synthetic report\r\n"

    with create_run_directory(runs_root, "run-20260722") as run:
        report = run.write_evidence(
            "reports/summary.txt",
            text_bytes,
            media_type="text/plain",
            sensitivity=Sensitivity.INTERNAL,
        )
        evidence = run.write_evidence(
            "evidence/observation.json",
            json_bytes,
            media_type="application/json",
            sensitivity=Sensitivity.CONFIDENTIAL,
        )
        finalized = run.finalize_manifest()

        assert report.sha256 == hashlib.sha256(text_bytes).hexdigest()
        assert evidence.sha256 == hashlib.sha256(json_bytes).hexdigest()
        assert (run.path / "evidence" / "observation.json").read_bytes() == json_bytes
        assert finalized.to_bytes() == (run.path / MANIFEST_FILENAME).read_bytes()
        assert finalized.sha256 == hashlib.sha256(finalized.to_bytes()).hexdigest()

    decoded = json.loads((runs_root / "run-20260722" / MANIFEST_FILENAME).read_bytes())
    assert [item["path"] for item in decoded["artifacts"]] == [
        "evidence/observation.json",
        "reports/summary.txt",
    ]
    assert decoded["artifacts"][0]["media_type"] == "application/json"
    assert decoded["artifacts"][0]["sensitivity"] == "confidential"

    verification = verify_run_integrity(runs_root / "run-20260722")
    assert verification.valid
    assert verification.run_id == "run-20260722"
    assert verification.artifacts_checked == _EXPECTED_ARTIFACT_COUNT
    assert verification.issues == ()


def test_run_creation_is_exclusive(tmp_path: Path) -> None:
    """An existing run directory is never adopted or overwritten."""
    runs_root = tmp_path / "runs"
    first = create_run_directory(runs_root, "same-run")
    try:
        with pytest.raises(RunAlreadyExistsError, match="already exists"):
            create_run_directory(runs_root, "same-run")
    finally:
        first.close()


def test_finalized_run_refuses_all_writer_mutation(tmp_path: Path) -> None:
    """The manifest marker makes the run immutable through the writer API."""
    with create_run_directory(tmp_path / "runs", "final-run") as run:
        run.write_evidence(
            "evidence/item.json",
            b"{}",
            media_type="application/json",
            sensitivity=Sensitivity.INTERNAL,
        )
        run.finalize_manifest()

        with pytest.raises(RunFinalizedError, match="cannot be modified"):
            run.write_evidence(
                "evidence/later.json",
                b"{}",
                media_type="application/json",
                sensitivity=Sensitivity.INTERNAL,
            )
        with pytest.raises(RunFinalizedError, match="cannot be modified"):
            run.finalize_manifest()


def test_evidence_write_never_overwrites_existing_path(tmp_path: Path) -> None:
    """Atomic creation fails closed when an artifact name already exists."""
    with create_run_directory(tmp_path / "runs", "no-overwrite") as run:
        run.write_evidence(
            "evidence/item.json",
            b"first",
            media_type="application/json",
            sensitivity=Sensitivity.INTERNAL,
        )

        with pytest.raises(EvidenceAlreadyExistsError, match="already exists"):
            run.write_evidence(
                "evidence/item.json",
                b"second",
                media_type="application/json",
                sensitivity=Sensitivity.INTERNAL,
            )

        assert (run.path / "evidence" / "item.json").read_bytes() == b"first"


@pytest.mark.parametrize(
    "run_id",
    ["../escape", "nested/run", "/absolute", "..", ".", "back\\slash"],
)
def test_run_id_rejects_traversal(tmp_path: Path, run_id: str) -> None:
    """A run identifier is exactly one portable path component."""
    with pytest.raises(ValueError, match="run_id"):
        create_run_directory(tmp_path / "runs", run_id)


@pytest.mark.parametrize(
    "relative_path",
    [
        "../escape.json",
        "evidence/../../escape.json",
        "/absolute.json",
        "evidence//item.json",
        "evidence/./item.json",
        "evidence\\item.json",
        "manifest.json",
        ".cai-staging/item.json",
    ],
)
def test_evidence_path_rejects_traversal(
    tmp_path: Path,
    relative_path: str,
) -> None:
    """Artifact paths cannot escape, alias, or occupy reserved storage names."""
    with (
        create_run_directory(tmp_path / "runs", "traversal-run") as run,
        pytest.raises(ValueError, match="artifact path"),
    ):
        run.write_evidence(
            relative_path,
            b"synthetic",
            media_type="text/plain",
            sensitivity=Sensitivity.INTERNAL,
        )


def test_write_rejects_symlinked_parent_escape(tmp_path: Path) -> None:
    """A symlink inserted below the run cannot redirect an evidence write."""
    outside = tmp_path / "outside"
    outside.mkdir()
    with create_run_directory(tmp_path / "runs", "symlink-parent") as run:
        (run.path / "escape").symlink_to(outside, target_is_directory=True)

        with pytest.raises(UnsafeEvidencePathError, match="escape"):
            run.write_evidence(
                "escape/stolen.txt",
                b"must stay inside",
                media_type="text/plain",
                sensitivity=Sensitivity.RESTRICTED,
            )

        assert not (outside / "stolen.txt").exists()


def test_write_rejects_symlinked_destination(tmp_path: Path) -> None:
    """An existing leaf symlink is not replaced by an atomic write."""
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside")
    with create_run_directory(tmp_path / "runs", "symlink-leaf") as run:
        evidence_directory = run.path / "evidence"
        evidence_directory.mkdir()
        (evidence_directory / "item.txt").symlink_to(outside)

        with pytest.raises(EvidenceAlreadyExistsError, match="already exists"):
            run.write_evidence(
                "evidence/item.txt",
                b"replacement",
                media_type="text/plain",
                sensitivity=Sensitivity.INTERNAL,
            )

        assert outside.read_bytes() == b"outside"


def test_create_rejects_symlinked_runs_root(tmp_path: Path) -> None:
    """The configured root itself cannot silently redirect run creation."""
    actual_root = tmp_path / "actual"
    actual_root.mkdir()
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(actual_root, target_is_directory=True)

    with pytest.raises(UnsafeEvidencePathError):
        create_run_directory(linked_root, "escaped-run")

    assert not (actual_root / "escaped-run").exists()


def test_create_and_verify_reject_intermediate_root_symlink(tmp_path: Path) -> None:
    """No configured path component may redirect creation or verification."""
    actual_root = tmp_path / "actual"
    actual_root.mkdir()
    visible_root = tmp_path / "visible"
    visible_root.mkdir()
    (visible_root / "redirect").symlink_to(actual_root, target_is_directory=True)

    with pytest.raises(UnsafeEvidencePathError):
        create_run_directory(visible_root / "redirect" / "runs", "escaped-run")

    with create_run_directory(actual_root / "runs", "real-run") as run:
        run.finalize_manifest()
        actual_run = run.path

    verification = verify_run_integrity(visible_root / "redirect" / "runs" / "real-run")
    assert actual_run.exists()
    assert not verification.valid
    assert verification.issues[0].code is IntegrityIssueCode.UNSAFE_PATH


def test_offline_verifier_rejects_symlinked_run(tmp_path: Path) -> None:
    """Offline verification never follows its run-directory argument."""
    target = tmp_path / "target"
    target.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)

    verification = verify_run_integrity(linked)

    assert not verification.valid
    assert verification.issues[0].code is IntegrityIssueCode.UNSAFE_PATH


def test_offline_verifier_detects_same_size_tampering(tmp_path: Path) -> None:
    """Byte changes are detected even when the artifact length is unchanged."""
    with create_run_directory(tmp_path / "runs", "tampered-run") as run:
        run.write_evidence(
            "evidence/item.txt",
            b"original",
            media_type="text/plain",
            sensitivity=Sensitivity.INTERNAL,
        )
        run.finalize_manifest()
        run_path = run.path

    (run_path / "evidence" / "item.txt").write_bytes(b"tampered")
    verification = verify_run_integrity(run_path)

    assert not verification.valid
    assert len(verification.issues) == 1
    assert verification.issues[0].code is IntegrityIssueCode.DIGEST_MISMATCH
    assert verification.issues[0].path == "evidence/item.txt"


def test_offline_verifier_detects_manifest_completeness_changes(
    tmp_path: Path,
) -> None:
    """Missing and extra files cannot be hidden by otherwise valid hashes."""
    with create_run_directory(tmp_path / "runs", "complete-run") as run:
        run.write_evidence(
            "evidence/expected.txt",
            b"expected",
            media_type="text/plain",
            sensitivity=Sensitivity.INTERNAL,
        )
        run.finalize_manifest()
        run_path = run.path

    (run_path / "evidence" / "expected.txt").unlink()
    (run_path / "unexpected.txt").write_bytes(b"unexpected")
    verification = verify_run_integrity(run_path)

    assert [issue.code for issue in verification.issues] == [
        IntegrityIssueCode.MISSING_ARTIFACT,
        IntegrityIssueCode.UNEXPECTED_ARTIFACT,
    ]


def test_manifest_traversal_is_invalid_without_reading_outside(
    tmp_path: Path,
) -> None:
    """A malicious manifest path is rejected before artifact lookup."""
    run_path = tmp_path / "run"
    run_path.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside")
    malicious_manifest = {
        "artifacts": [
            {
                "media_type": "text/plain",
                "path": "../outside.txt",
                "sensitivity": "internal",
                "sha256": hashlib.sha256(b"outside").hexdigest(),
                "size_bytes": len(b"outside"),
            }
        ],
        "run_id": "malicious-run",
        "schema_version": "1",
    }
    (run_path / MANIFEST_FILENAME).write_bytes(
        json.dumps(
            malicious_manifest,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    )

    verification = verify_run_integrity(run_path)

    assert not verification.valid
    assert verification.issues[0].code is IntegrityIssueCode.INVALID_MANIFEST
    assert outside.read_bytes() == b"outside"


def test_malformed_large_integer_returns_invalid_manifest(tmp_path: Path) -> None:
    """JSON parser resource errors become a deterministic invalid result."""
    run_path = tmp_path / "run"
    run_path.mkdir()
    huge_integer = b"9" * 5_000
    manifest = (
        b'{"artifacts":[{"media_type":"text/plain","path":"item.txt",'
        b'"sensitivity":"internal","sha256":"'
        + (b"0" * 64)
        + b'","size_bytes":'
        + huge_integer
        + b'}],"run_id":"parser-run","schema_version":"1"}'
    )
    (run_path / MANIFEST_FILENAME).write_bytes(manifest)

    verification = verify_run_integrity(run_path)

    assert not verification.valid
    assert verification.issues[0].code is IntegrityIssueCode.INVALID_MANIFEST


def test_offline_verifier_bounds_unexpected_file_size(tmp_path: Path) -> None:
    """A sparse untrusted extra file is rejected without hashing its extent."""
    with create_run_directory(tmp_path / "runs", "bounded-scan") as run:
        run.finalize_manifest()
        run_path = run.path

    with (run_path / "oversized.bin").open("wb") as oversized:
        oversized.truncate(MAX_ARTIFACT_BYTES + 1)

    verification = verify_run_integrity(run_path)

    assert not verification.valid
    assert verification.issues[0].code is IntegrityIssueCode.RESOURCE_LIMIT
    assert verification.issues[0].path == "oversized.bin"


def test_manifest_is_not_charged_to_artifact_entry_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Writer and verifier accept the same exact artifact-tree entry boundary."""
    monkeypatch.setattr("cai_verify.evidence._filesystem.MAX_SCAN_ENTRIES", 2)
    with create_run_directory(tmp_path / "runs", "entry-boundary") as run:
        run.write_evidence(
            "evidence/item.txt",
            b"x",
            media_type="text/plain",
            sensitivity=Sensitivity.INTERNAL,
        )
        run.finalize_manifest()
        run_path = run.path

    assert verify_run_integrity(run_path).valid


def test_scan_byte_budget_uses_hashed_inode_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Aggregate limits charge the exact opened bytes, not earlier path metadata."""
    with create_run_directory(tmp_path / "runs", "byte-boundary") as run:
        run.write_evidence(
            "one.txt",
            b"aa",
            media_type="text/plain",
            sensitivity=Sensitivity.INTERNAL,
        )
        run.write_evidence(
            "two.txt",
            b"bb",
            media_type="text/plain",
            sensitivity=Sensitivity.INTERNAL,
        )
        run.finalize_manifest()
        run_path = run.path

    monkeypatch.setattr("cai_verify.evidence._filesystem.MAX_RUN_ARTIFACT_BYTES", 3)
    verification = verify_run_integrity(run_path)

    assert not verification.valid
    assert verification.issues[0].code is IntegrityIssueCode.RESOURCE_LIMIT


def test_evidence_publication_detects_staging_name_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The published artifact must be the exact inode opened and hashed."""
    original_link = os.link

    def replacing_link(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        assert src_dir_fd is not None
        os.unlink(source, dir_fd=src_dir_fd)
        replacement_fd = os.open(
            source,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=src_dir_fd,
        )
        try:
            os.write(replacement_fd, b"attacker replacement")
        finally:
            os.close(replacement_fd)
        original_link(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr("cai_verify.evidence.storage.os.link", replacing_link)
    with create_run_directory(tmp_path / "runs", "inode-race") as run:
        with pytest.raises(UnsafeEvidencePathError):
            run.write_evidence(
                "evidence/item.txt",
                b"trusted bytes",
                media_type="text/plain",
                sensitivity=Sensitivity.INTERNAL,
            )

        assert not (run.path / "evidence" / "item.txt").exists()
        assert list((run.path / ".cai-staging").iterdir()) == []


def test_manifest_publication_detects_staging_name_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The final marker cannot cover a different inode than returned to callers."""
    original_link = os.link

    def replacing_link(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        assert src_dir_fd is not None
        os.unlink(source, dir_fd=src_dir_fd)
        replacement_fd = os.open(
            source,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=src_dir_fd,
        )
        try:
            os.write(replacement_fd, b"attacker manifest")
        finally:
            os.close(replacement_fd)
        original_link(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    with create_run_directory(tmp_path / "runs", "manifest-inode-race") as run:
        monkeypatch.setattr("cai_verify.evidence.storage.os.link", replacing_link)
        with pytest.raises(UnsafeEvidencePathError):
            run.finalize_manifest()

        assert not (run.path / MANIFEST_FILENAME).exists()


def test_finalize_refuses_manifest_larger_than_verifier_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The writer cannot publish bytes its paired verifier would reject by size."""
    with create_run_directory(tmp_path / "runs", "large-manifest") as run:
        monkeypatch.setattr("cai_verify.evidence.storage.MAX_MANIFEST_BYTES", 16)

        with pytest.raises(IncompleteRunError, match="maximum supported size"):
            run.finalize_manifest()

        assert not (run.path / MANIFEST_FILENAME).exists()


def test_short_os_writes_are_completed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The writer loops until every requested byte reaches the staging file."""
    original_write = os.write

    def short_write(descriptor: int, content: memoryview) -> int:
        return original_write(descriptor, content[:2])

    monkeypatch.setattr("cai_verify.evidence.storage.os.write", short_write)
    content = b"a deliberately longer synthetic artifact"
    with create_run_directory(tmp_path / "runs", "short-write") as run:
        run.write_evidence(
            "evidence/item.txt",
            content,
            media_type="text/plain",
            sensitivity=Sensitivity.INTERNAL,
        )
        run.finalize_manifest()
        run_path = run.path

    assert (run_path / "evidence" / "item.txt").read_bytes() == content
    assert verify_run_integrity(run_path).valid


def test_interrupted_partial_write_leaves_no_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exception after a short write removes staging and target entries."""
    original_write = os.write
    write_calls = 0

    def interrupted_write(descriptor: int, content: memoryview) -> int:
        nonlocal write_calls
        write_calls += 1
        if write_calls == 1:
            return original_write(descriptor, content[:3])
        message = "synthetic interrupted write"
        raise OSError(message)

    monkeypatch.setattr("cai_verify.evidence.storage.os.write", interrupted_write)
    with create_run_directory(tmp_path / "runs", "interrupted-write") as run:
        with pytest.raises(OSError, match="synthetic interrupted"):
            run.write_evidence(
                "evidence/item.txt",
                b"partial content must not become visible",
                media_type="text/plain",
                sensitivity=Sensitivity.INTERNAL,
            )

        assert not (run.path / "evidence" / "item.txt").exists()
        assert list((run.path / ".cai-staging").iterdir()) == []


def test_finalize_refuses_crash_leftover_partial_file(tmp_path: Path) -> None:
    """A simulated process-crash staging file prevents a misleading manifest."""
    with create_run_directory(tmp_path / "runs", "crash-leftover") as run:
        (run.path / ".cai-staging" / "orphan.partial").write_bytes(b"partial")

        with pytest.raises(IncompleteRunError, match="interrupted"):
            run.finalize_manifest()

        assert not (run.path / MANIFEST_FILENAME).exists()


def test_interrupted_manifest_write_leaves_run_unfinalized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Partial manifest staging bytes never become the finalization marker."""
    original_write = os.write
    write_calls = 0

    def interrupted_write(descriptor: int, content: memoryview) -> int:
        nonlocal write_calls
        write_calls += 1
        if write_calls == 1:
            return original_write(descriptor, content[:3])
        message = "synthetic interrupted manifest write"
        raise OSError(message)

    with create_run_directory(tmp_path / "runs", "manifest-interrupted") as run:
        monkeypatch.setattr("cai_verify.evidence.storage.os.write", interrupted_write)
        with pytest.raises(OSError, match="interrupted manifest"):
            run.finalize_manifest()

        assert not (run.path / MANIFEST_FILENAME).exists()
        assert not any(
            path.name.startswith(".cai-manifest-") for path in run.path.parent.iterdir()
        )


def test_finalize_refuses_artifact_changed_before_manifest(tmp_path: Path) -> None:
    """Finalization does not bless bytes changed after their atomic write."""
    with create_run_directory(tmp_path / "runs", "pre-finalize-tamper") as run:
        run.write_evidence(
            "evidence/item.txt",
            b"original",
            media_type="text/plain",
            sensitivity=Sensitivity.INTERNAL,
        )
        (run.path / "evidence" / "item.txt").write_bytes(b"tampered")

        with pytest.raises(IncompleteRunError, match="changed"):
            run.finalize_manifest()

        assert not (run.path / MANIFEST_FILENAME).exists()
