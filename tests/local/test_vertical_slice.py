"""End-to-end tests for secure and intentionally vulnerable local modes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

import cai_verify.adapters.http as http_adapter
from cai_verify.cli import app
from cai_verify.core import AssertionStatus, CliExitCode
from cai_verify.evidence import IntegrityIssueCode, verify_run_integrity
from cai_verify.local import SyntheticTelemetryMode
from cai_verify.local.runner import (
    SYNTHETIC_CANARY,
    LocalRunOptions,
    load_suite,
    run_local_suite,
)

if TYPE_CHECKING:
    from cai_verify.config import VerificationSuite
    from cai_verify.local.runner import LocalRunResult

_PROJECT_ROOT = Path(__file__).parents[2]
_SUITE_PATH = _PROJECT_ROOT / "examples" / "local" / "synthetic-suite.json"
_RAW_PRINCIPAL = b"synthetic-healthcare-user"


@pytest.mark.allow_hosts(["127.0.0.1"])
def test_secure_mode_passes_and_vulnerable_mode_fails_only_canary(
    tmp_path: Path,
) -> None:
    """One identical suite proves both sides of the intended telemetry control."""
    suite = load_suite(_SUITE_PATH)

    secure = _run(suite, tmp_path / "secure", "secure-run", "secure")
    vulnerable = _run(
        suite,
        tmp_path / "vulnerable",
        "vulnerable-run",
        "vulnerable",
    )

    assert secure.status is AssertionStatus.PASS
    assert secure.exit_code is CliExitCode.SUCCESS
    assert {result.status for result in secure.results} == {AssertionStatus.PASS}
    assert vulnerable.status is AssertionStatus.FAIL
    assert vulnerable.exit_code is CliExitCode.ASSERTION_FAILED
    vulnerable_statuses = {
        result.assertion_id: result.status for result in vulnerable.results
    }
    assert vulnerable_statuses == {
        "application-status": AssertionStatus.PASS,
        "audit-event-present": AssertionStatus.PASS,
        "audit-principal-correlated": AssertionStatus.PASS,
        "telemetry-canary-absent": AssertionStatus.FAIL,
    }
    assert b"Overall: PASS (exit 0)" in secure.terminal_report
    assert b"Overall: FAIL (exit 1)" in vulnerable.terminal_report
    assert json.loads(secure.json_report)["aggregate_status"] == "PASS"
    assert json.loads(vulnerable.json_report)["aggregate_status"] == "FAIL"


@pytest.mark.allow_hosts(["127.0.0.1"])
def test_local_run_is_byte_deterministic_and_excludes_sensitive_source_values(
    tmp_path: Path,
) -> None:
    """Ephemeral ports and vulnerable raw telemetry never enter evidence bytes."""
    suite = load_suite(_SUITE_PATH)
    first = _run(suite, tmp_path / "first", "deterministic-run", "vulnerable")
    second = _run(suite, tmp_path / "second", "deterministic-run", "vulnerable")

    assert _run_files(first.evidence_path) == _run_files(second.evidence_path)
    for content in _run_files(first.evidence_path).values():
        assert SYNTHETIC_CANARY.encode() not in content
        assert _RAW_PRINCIPAL not in content
    assert verify_run_integrity(first.evidence_path).valid
    assert verify_run_integrity(second.evidence_path).valid


@pytest.mark.allow_hosts(["127.0.0.1"])
def test_cli_exit_codes_reports_and_tamper_detection(tmp_path: Path) -> None:
    """Automation receives 0/1 for outcomes and 2 for modified evidence."""
    runner = CliRunner()
    secure_root = tmp_path / "secure-evidence"
    vulnerable_root = tmp_path / "vulnerable-evidence"

    secure = runner.invoke(
        app,
        [
            "run-local",
            str(_SUITE_PATH),
            "--mode",
            "secure",
            "--run-id",
            "secure-cli",
            "--evidence-root",
            str(secure_root),
            "--report",
            "json",
        ],
    )
    vulnerable = runner.invoke(
        app,
        [
            "run-local",
            str(_SUITE_PATH),
            "--mode",
            "vulnerable",
            "--run-id",
            "vulnerable-cli",
            "--evidence-root",
            str(vulnerable_root),
        ],
    )

    assert secure.exit_code == 0
    assert json.loads(secure.stdout)["exit_code"] == 0
    assert vulnerable.exit_code == 1
    assert "Overall: FAIL (exit 1)" in vulnerable.stdout

    run_path = secure_root / "secure-cli"
    valid = runner.invoke(app, ["verify-evidence", str(run_path), "--report", "json"])
    assert valid.exit_code == 0
    assert json.loads(valid.stdout)["valid"] is True

    report_path = run_path / "reports" / "terminal.txt"
    report_path.write_bytes(report_path.read_bytes() + b"tampered\n")
    invalid = runner.invoke(
        app,
        ["verify-evidence", str(run_path), "--report", "json"],
    )
    invalid_payload = json.loads(invalid.stdout)
    assert invalid.exit_code == int(CliExitCode.EXECUTION_ERROR)
    assert invalid_payload["valid"] is False
    assert invalid_payload["issues"] == [
        {
            "code": IntegrityIssueCode.SIZE_MISMATCH.value,
            "path": "reports/terminal.txt",
        },
        {
            "code": IntegrityIssueCode.DIGEST_MISMATCH.value,
            "path": "reports/terminal.txt",
        },
    ]


@pytest.mark.allow_hosts(["127.0.0.1"])
def test_transport_error_remains_exit_two(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing action and telemetry evidence cannot mask an execution error."""
    monkeypatch.setattr(http_adapter, "_send_request", lambda **_kwargs: None)

    result = _run(
        load_suite(_SUITE_PATH),
        tmp_path / "transport-error",
        "transport-error",
        "secure",
    )

    assert result.status is AssertionStatus.ERROR
    assert result.exit_code is CliExitCode.EXECUTION_ERROR
    assert {item.assertion_id: item.status for item in result.results} == {
        "application-status": AssertionStatus.ERROR,
        "audit-event-present": AssertionStatus.ERROR,
        "audit-principal-correlated": AssertionStatus.ERROR,
        "telemetry-canary-absent": AssertionStatus.INCONCLUSIVE,
    }


def test_suite_loader_rejects_duplicate_and_oversized_json(tmp_path: Path) -> None:
    """Untrusted suite files cannot exploit duplicate fields or unbounded input."""
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schemaVersion":"1alpha1","schemaVersion":"1alpha1"}',
        encoding="utf-8",
    )
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * (1024 * 1024) + b"}")

    with pytest.raises(ValueError, match="duplicate-free"):
        load_suite(duplicate)
    with pytest.raises(ValueError, match="maximum supported size"):
        load_suite(oversized)


def _run(
    suite: VerificationSuite,
    evidence_root: Path,
    run_id: str,
    mode: str,
) -> LocalRunResult:
    return run_local_suite(
        suite,
        LocalRunOptions(
            mode=SyntheticTelemetryMode(mode),
            evidence_root=evidence_root,
            run_id=run_id,
        ),
    )


def _run_files(run_path: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(run_path)): path.read_bytes()
        for path in sorted(run_path.rglob("*"))
        if path.is_file()
    }
