"""Tests for the command-line interface."""

from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

from typer.testing import CliRunner

from cai_verify import __version__
from cai_verify.aws import (
    AwsDoctorResult,
    AwsExecutionPolicy,
    AwsIdentityCheck,
    AwsRetrievalRunResult,
    RetrievalCorrelationState,
    RetrievalDoctorResult,
    RetrievalReadinessCheck,
)
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
        execution_policy: AwsExecutionPolicy,
        environment: Mapping[str, str],
    ) -> AwsDoctorResult:
        assert execution_policy is not None
        assert environment is not None
        return doctor_result

    monkeypatch.setattr("cai_verify.cli.run_aws_doctor", successful_doctor)
    suite_path = Path(__file__).parents[1] / "examples/local/synthetic-suite.json"
    policy_path = (
        Path(__file__).parents[1] / "examples/aws/reciprocal-retrieval-policy.json"
    )

    result = runner.invoke(
        app,
        [
            "doctor",
            "aws",
            str(suite_path),
            "--execution-policy",
            str(policy_path),
            "--report",
            "json",
        ],
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
        execution_policy: AwsExecutionPolicy,
        environment: Mapping[str, str],
    ) -> AwsDoctorResult:
        del environment, execution_policy
        raise RuntimeError(secret)

    monkeypatch.setattr("cai_verify.cli.run_aws_doctor", fail_doctor)
    suite_path = Path(__file__).parents[1] / "examples/local/synthetic-suite.json"
    policy_path = (
        Path(__file__).parents[1] / "examples/aws/reciprocal-retrieval-policy.json"
    )

    result = runner.invoke(
        app,
        [
            "doctor",
            "aws",
            str(suite_path),
            "--execution-policy",
            str(policy_path),
        ],
    )

    assert result.exit_code == int(CliExitCode.EXECUTION_ERROR)
    assert result.stdout == ""
    assert result.stderr == "AWS doctor failed\n"
    assert secret not in result.output


def test_retrieval_doctor_command_renders_canonical_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The retrieval doctor has an independent version-1 CLI result."""
    doctor_result = RetrievalDoctorResult(
        target_id="synthetic-target",
        target_environment="sandbox",
        region="eu-west-2",
        ready=True,
        checks=(
            RetrievalReadinessCheck(
                scenario_id="synthetic-scenario",
                assertion_id="synthetic-assertion",
                action_id="synthetic-action",
                probe_id="synthetic-probe",
                configuration_compatible=True,
                action_identity_ready=True,
                evidence_identity_ready=True,
                canary_contract_ready=True,
                source_accessible=True,
                correlation_state=RetrievalCorrelationState.RUNTIME_REQUIRED,
                issues=(),
            ),
        ),
        issues=(),
    )

    def successful_doctor(
        _suite: VerificationSuite,
        *,
        execution_policy: AwsExecutionPolicy,
        environment: Mapping[str, str],
    ) -> RetrievalDoctorResult:
        assert execution_policy is not None
        assert environment is not None
        return doctor_result

    monkeypatch.setattr("cai_verify.cli.run_retrieval_doctor", successful_doctor)
    suite_path = Path(__file__).parents[1] / "examples/local/synthetic-suite.json"
    policy_path = (
        Path(__file__).parents[1] / "examples/aws/reciprocal-retrieval-policy.json"
    )

    result = runner.invoke(
        app,
        [
            "doctor",
            "retrieval",
            str(suite_path),
            "--execution-policy",
            str(policy_path),
            "--report",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert result.stdout == doctor_result.to_json_bytes().decode()


def test_retrieval_doctor_not_ready_and_unexpected_failure_exit_two(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Not-ready output and unexpected errors both use the operational exit."""
    not_ready = RetrievalDoctorResult(
        target_id="synthetic-target",
        target_environment="sandbox",
        region="eu-west-2",
        ready=False,
        checks=(),
        issues=(),
    )

    def unsuccessful_doctor(
        _suite: VerificationSuite,
        *,
        execution_policy: AwsExecutionPolicy,
        environment: Mapping[str, str],
    ) -> RetrievalDoctorResult:
        del environment, execution_policy
        return not_ready

    monkeypatch.setattr("cai_verify.cli.run_retrieval_doctor", unsuccessful_doctor)
    suite_path = Path(__file__).parents[1] / "examples/local/synthetic-suite.json"
    policy_path = (
        Path(__file__).parents[1] / "examples/aws/reciprocal-retrieval-policy.json"
    )
    result = runner.invoke(
        app,
        [
            "doctor",
            "retrieval",
            str(suite_path),
            "--execution-policy",
            str(policy_path),
        ],
    )

    assert result.exit_code == int(CliExitCode.EXECUTION_ERROR)
    assert result.stdout == not_ready.to_terminal_bytes().decode()

    secret = "retrieval-doctor-exception-secret-must-not-leak"  # noqa: S105

    def fail_doctor(
        _suite: VerificationSuite,
        *,
        execution_policy: AwsExecutionPolicy,
        environment: Mapping[str, str],
    ) -> RetrievalDoctorResult:
        del environment, execution_policy
        raise RuntimeError(secret)

    monkeypatch.setattr("cai_verify.cli.run_retrieval_doctor", fail_doctor)
    failed = runner.invoke(
        app,
        [
            "doctor",
            "retrieval",
            str(suite_path),
            "--execution-policy",
            str(policy_path),
        ],
    )
    assert failed.exit_code == int(CliExitCode.EXECUTION_ERROR)
    assert failed.stdout == ""
    assert failed.stderr == "retrieval doctor failed\n"
    assert secret not in failed.output


def test_minimal_aws_retrieval_runner_cli_renders_and_redacts_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The one-chain runner exposes reports and one fixed unexpected error."""
    run_result = cast(
        "AwsRetrievalRunResult",
        SimpleNamespace(
            exit_code=CliExitCode.SUCCESS,
            json_report=b'{"schema_version":"1","status":"PASS"}',
            terminal_report=b"Retrieval assertion: PASS\n",
        ),
    )

    def successful_run(
        _suite: VerificationSuite,
        _options: object,
    ) -> AwsRetrievalRunResult:
        return run_result

    monkeypatch.setattr("cai_verify.cli.run_aws_retrieval_chain", successful_run)
    suite_path = Path(__file__).parents[1] / "examples/local/synthetic-suite.json"
    policy_path = (
        Path(__file__).parents[1] / "examples/aws/reciprocal-retrieval-policy.json"
    )
    result = runner.invoke(
        app,
        [
            "run-aws-retrieval",
            str(suite_path),
            "--assertion-id",
            "synthetic-assertion",
            "--execution-policy",
            str(policy_path),
            "--run-id",
            "synthetic-run",
            "--report",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert result.stdout == run_result.json_report.decode()

    secret = "aws-retrieval-runner-secret-must-not-leak"  # noqa: S105

    def fail_run(_suite: VerificationSuite, _options: object) -> AwsRetrievalRunResult:
        raise RuntimeError(secret)

    monkeypatch.setattr("cai_verify.cli.run_aws_retrieval_chain", fail_run)
    failed = runner.invoke(
        app,
        [
            "run-aws-retrieval",
            str(suite_path),
            "--assertion-id",
            "synthetic-assertion",
            "--execution-policy",
            str(policy_path),
            "--run-id",
            "synthetic-run",
        ],
    )
    assert failed.exit_code == int(CliExitCode.EXECUTION_ERROR)
    assert failed.stdout == ""
    assert failed.stderr == "AWS retrieval run failed\n"
    assert secret not in failed.output


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


def test_ui_command_forwards_only_loopback_launch_options(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The CLI exposes no host override and honors automation browser suppression."""
    calls: list[tuple[Path, int, bool]] = []

    def run_console(
        *,
        evidence_root: Path,
        port: int,
        open_browser: bool,
    ) -> None:
        calls.append((evidence_root, port, open_browser))

    monkeypatch.setattr("cai_verify.ui.run_console", run_console)

    result = runner.invoke(
        app,
        [
            "ui",
            "--evidence-root",
            str(tmp_path),
            "--port",
            "43123",
            "--no-open",
        ],
    )

    assert result.exit_code == 0
    assert result.stdout == ""
    assert calls == [(tmp_path.resolve(), 43123, False)]
    help_result = runner.invoke(app, ["ui", "--help"])
    assert help_result.exit_code == 0
    assert "--evidence-root" in help_result.stdout
    assert "--port" in help_result.stdout
    assert "--no-open" in help_result.stdout
    assert "--host" not in help_result.stdout


def test_ui_command_redacts_optional_dependency_and_runtime_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Browser, bind, and optional-extra details collapse to one diagnostic."""
    secret = "synthetic-ui-launch-secret-must-not-leak"  # noqa: S105

    def fail_console(**_kwargs: object) -> None:
        raise OSError(secret)

    monkeypatch.setattr("cai_verify.ui.run_console", fail_console)

    result = runner.invoke(app, ["ui", "--no-open"])

    assert result.exit_code == int(CliExitCode.EXECUTION_ERROR)
    assert result.stdout == ""
    assert result.stderr == "local console failed; install cai-verify[aws,ui]\n"
    assert secret not in result.output
