"""Tests for the command-line interface."""

from pathlib import Path
from typing import TYPE_CHECKING

from typer.testing import CliRunner

from cai_verify import __version__
from cai_verify.aws import AwsDoctorResult, AwsIdentityCheck
from cai_verify.cli import app
from cai_verify.core import CliExitCode

if TYPE_CHECKING:
    from collections.abc import Mapping

    import pytest

    from cai_verify.config import VerificationSuite

runner = CliRunner()
USAGE_ERROR = 2


def test_version_reports_installed_package_version() -> None:
    """The version command emits one stable, machine-readable line."""
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout == f"{__version__}\n"


def test_root_displays_help_and_returns_usage_error() -> None:
    """Invoking the command group without a command explains valid usage."""
    result = runner.invoke(app)

    assert result.exit_code == USAGE_ERROR
    assert "Usage:" in result.stdout
    assert "doctor" in result.stdout
    assert "version" in result.stdout


def test_nested_aws_doctor_command_renders_canonical_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The AWS command is namespaced under cai-verify and returns stable JSON."""
    doctor_result = AwsDoctorResult(
        target_id="synthetic-target",
        target_environment="sandbox",
        region="eu-west-2",
        ready=True,
        identities=(
            AwsIdentityCheck(
                identity_id="synthetic-identity",
                identity_type="awsCurrent",
                ready=True,
                account_matches=True,
                partition_matches=True,
                expires_at=None,
                issues=(),
            ),
        ),
        issues=(),
    )

    def successful_doctor(
        _suite: VerificationSuite,
        *,
        environment: Mapping[str, str],
    ) -> AwsDoctorResult:
        assert environment is not None
        return doctor_result

    monkeypatch.setattr("cai_verify.cli.run_aws_doctor", successful_doctor)
    suite_path = Path(__file__).parents[1] / "examples/local/synthetic-suite.json"

    result = runner.invoke(
        app,
        ["doctor", "aws", str(suite_path), "--report", "json"],
    )

    assert result.exit_code == 0
    assert result.stdout == doctor_result.to_json_bytes().decode()


def test_aws_doctor_failure_redacts_exception_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Internal SDK failures cannot reach the public CLI diagnostic."""
    secret = "aws-doctor-exception-secret-must-not-leak"  # noqa: S105

    def fail_doctor(
        _suite: VerificationSuite,
        *,
        environment: Mapping[str, str],
    ) -> AwsDoctorResult:
        del environment
        raise RuntimeError(secret)

    monkeypatch.setattr("cai_verify.cli.run_aws_doctor", fail_doctor)
    suite_path = Path(__file__).parents[1] / "examples/local/synthetic-suite.json"

    result = runner.invoke(app, ["doctor", "aws", str(suite_path)])

    assert result.exit_code == int(CliExitCode.EXECUTION_ERROR)
    assert result.stdout == ""
    assert result.stderr == "AWS doctor failed\n"
    assert secret not in result.output


def test_local_run_failure_redacts_exception_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Secret-bearing internal errors collapse to one stable public diagnostic."""
    secret = "synthetic-cli-secret-must-not-leak"  # noqa: S105

    def fail_load(_path: object) -> None:
        raise RuntimeError(secret)

    monkeypatch.setattr("cai_verify.cli.load_suite", fail_load)
    suite_path = Path(__file__).parents[1] / "examples/local/synthetic-suite.json"

    result = runner.invoke(
        app,
        [
            "run-local",
            str(suite_path),
            "--mode",
            "secure",
            "--run-id",
            "redaction-test",
        ],
    )

    assert result.exit_code == int(CliExitCode.EXECUTION_ERROR)
    assert result.stdout == ""
    assert result.stderr == "local run failed\n"
    assert secret not in result.output
