"""Public-alpha CLI, installed-schema, and representation contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import pytest
from typer.testing import CliRunner

from cai_verify.cli import app
from cai_verify.core import CliExitCode, RedactedValue
from cai_verify.plugins import ActionExecutionResult, ActionOutcome

if TYPE_CHECKING:
    from cai_verify.aws import (
        AwsReciprocalRetrievalRunOptions,
        AwsReciprocalRetrievalRunResult,
    )
    from cai_verify.config import VerificationSuite

_ROOT = Path(__file__).parents[1]
_SUITE = _ROOT / "examples/aws/reciprocal-retrieval-suite.json"
_POLICY = _ROOT / "examples/aws/reciprocal-retrieval-policy.json"
_RUNNER = CliRunner()
_USAGE_ERROR = 2


@pytest.mark.parametrize(
    ("command", "schema_path"),
    [
        (
            "suite",
            _ROOT / "schemas/verification-suite-1alpha1.schema.json",
        ),
        (
            "aws-execution-policy",
            _ROOT / "schemas/aws-execution-policy-1alpha1.schema.json",
        ),
    ],
)
def test_schema_commands_emit_exact_installed_resource_bytes(
    command: str,
    schema_path: Path,
) -> None:
    """Schema commands preserve the reviewed build-time resources exactly."""
    result = _RUNNER.invoke(app, ["schema", command])

    assert result.exit_code == 0
    assert result.stderr == ""
    assert result.stdout.encode() == schema_path.read_bytes()


@pytest.mark.parametrize(
    "arguments",
    [
        ["doctor", "aws", str(_SUITE)],
        ["doctor", "retrieval", str(_SUITE)],
        [
            "run-aws-retrieval",
            str(_SUITE),
            "--assertion-id",
            "boundary-a",
            "--run-id",
            "public-alpha-run",
        ],
        [
            "run-aws-reciprocal-retrieval",
            str(_SUITE),
            "--scenario-id",
            "reciprocal-requester-retrieval",
            "--run-id",
            "public-alpha-run",
        ],
    ],
)
def test_every_aws_command_requires_execution_policy(
    arguments: list[str],
) -> None:
    """No AWS-capable command can enter its handler without operator policy."""
    result = _RUNNER.invoke(app, arguments)

    assert result.exit_code == _USAGE_ERROR
    assert "--execution-policy" in result.output


@pytest.mark.parametrize(
    ("exit_code", "status"),
    [
        (CliExitCode.SUCCESS, "PASS"),
        (CliExitCode.ASSERTION_FAILED, "FAIL"),
        (CliExitCode.EXECUTION_ERROR, "ERROR"),
        (CliExitCode.INCONCLUSIVE, "INCONCLUSIVE"),
    ],
)
@pytest.mark.parametrize("report_format", ["terminal", "json"])
def test_reciprocal_cli_preserves_normalized_exit_codes_and_reports(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    exit_code: CliExitCode,
    status: str,
    report_format: str,
) -> None:
    """Every normalized aggregate prints its selected report before exiting."""
    terminal_report = f"Reciprocal retrieval boundary: {status}\n".encode()
    json_report = f'{{"exit_code":{int(exit_code)},"status":"{status}"}}'.encode()
    run_result = cast(
        "AwsReciprocalRetrievalRunResult",
        SimpleNamespace(
            exit_code=exit_code,
            json_report=json_report,
            terminal_report=terminal_report,
        ),
    )
    captured_options: list[AwsReciprocalRetrievalRunOptions] = []

    def successful_run(
        _suite: VerificationSuite,
        options: AwsReciprocalRetrievalRunOptions,
    ) -> AwsReciprocalRetrievalRunResult:
        captured_options.append(options)
        return run_result

    monkeypatch.setattr(
        "cai_verify.cli.run_aws_reciprocal_retrieval",
        successful_run,
    )
    arguments = [
        "run-aws-reciprocal-retrieval",
        str(_SUITE),
        "--scenario-id",
        "reciprocal-requester-retrieval",
        "--execution-policy",
        str(_POLICY),
        "--run-id",
        "public-alpha-run",
        "--evidence-root",
        str(tmp_path),
        "--report",
        report_format,
    ]

    result = _RUNNER.invoke(app, arguments)

    assert result.exit_code == int(exit_code)
    expected_report = json_report if report_format == "json" else terminal_report
    assert result.stdout == expected_report.decode()
    assert result.stderr == ""
    assert len(captured_options) == 1
    assert captured_options[0].run_id == "public-alpha-run"
    assert captured_options[0].scenario_id == "reciprocal-requester-retrieval"
    assert captured_options[0].evidence_root == tmp_path


def test_reciprocal_operational_failure_has_only_fixed_stderr(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Operational details and policy content cannot escape the CLI boundary."""
    secret = "operational-correlation-and-sdk-diagnostic"  # noqa: S105

    def failed_run(
        _suite: VerificationSuite,
        _options: AwsReciprocalRetrievalRunOptions,
    ) -> AwsReciprocalRetrievalRunResult:
        raise RuntimeError(secret)

    monkeypatch.setattr(
        "cai_verify.cli.run_aws_reciprocal_retrieval",
        failed_run,
    )
    result = _RUNNER.invoke(
        app,
        [
            "run-aws-reciprocal-retrieval",
            str(_SUITE),
            "--scenario-id",
            "reciprocal-requester-retrieval",
            "--execution-policy",
            str(_POLICY),
            "--run-id",
            "public-alpha-run",
            "--evidence-root",
            str(tmp_path),
            "--report",
            "json",
        ],
    )

    assert result.exit_code == int(CliExitCode.EXECUTION_ERROR)
    assert result.stdout == ""
    assert result.stderr == "AWS reciprocal retrieval run failed\n"
    assert secret not in result.output
    assert "111122223333" not in result.output
    assert "retrieval.sandbox.example.test" not in result.output


def test_reciprocal_cli_uses_the_documented_default_evidence_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Omitting the root preserves the portable public-alpha default."""
    captured: list[AwsReciprocalRetrievalRunOptions] = []
    result_value = cast(
        "AwsReciprocalRetrievalRunResult",
        SimpleNamespace(
            exit_code=CliExitCode.SUCCESS,
            json_report=b'{"aggregate_status":"PASS"}',
            terminal_report=b"Overall: PASS\n",
        ),
    )

    def successful_run(
        _suite: VerificationSuite,
        options: AwsReciprocalRetrievalRunOptions,
    ) -> AwsReciprocalRetrievalRunResult:
        captured.append(options)
        return result_value

    monkeypatch.setattr(
        "cai_verify.cli.run_aws_reciprocal_retrieval",
        successful_run,
    )
    result = _RUNNER.invoke(
        app,
        [
            "run-aws-reciprocal-retrieval",
            str(_SUITE),
            "--scenario-id",
            "reciprocal-requester-retrieval",
            "--execution-policy",
            str(_POLICY),
            "--run-id",
            "default-evidence-root",
        ],
    )

    assert result.exit_code == 0
    assert captured[0].evidence_root == Path(".cai-verify/runs")


def test_action_execution_result_repr_hides_all_correlation_identifiers() -> None:
    """Representation hardening retains access without disclosing identifiers."""
    correlation = "application-correlation-secret"
    aws_request_id = "aws-request-id-secret"
    result = ActionExecutionResult(
        action_id="synthetic-action",
        outcome=ActionOutcome.SUCCEEDED,
        started_at=datetime(2026, 7, 28, 12, tzinfo=UTC),
        completed_at=datetime(2026, 7, 28, 12, 0, 1, tzinfo=UTC),
        observed=RedactedValue({"correlation_state": "MATCHED"}),
        correlation_ids=(correlation,),
        limitations=("Synthetic normalized result.",),
        aws_request_ids=(aws_request_id,),
    )

    rendered = repr(result)

    assert correlation not in rendered
    assert aws_request_id not in rendered
    assert "correlation_ids" not in rendered
    assert "aws_request_ids" not in rendered
    assert result.correlation_ids == (correlation,)
    assert result.aws_request_ids == (aws_request_id,)
