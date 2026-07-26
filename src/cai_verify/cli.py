"""Command-line interface for Cloud AI Control Verifier."""

import json
import os
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from cai_verify import __version__
from cai_verify.aws import (
    AwsRetrievalRunOptions,
    run_aws_doctor,
    run_aws_retrieval_chain,
    run_retrieval_doctor,
)
from cai_verify.config import load_suite
from cai_verify.core import CliExitCode
from cai_verify.evidence import verify_run_integrity
from cai_verify.local import SyntheticTelemetryMode  # noqa: TC001 - Typer runtime.
from cai_verify.local.runner import (
    LocalRunOptions,
    run_local_suite,
)

app = typer.Typer(
    add_completion=False,
    help="Verify security controls for cloud-hosted AI systems.",
    no_args_is_help=True,
)
doctor_app = typer.Typer(
    help="Check runtime prerequisites without executing verification actions.",
    no_args_is_help=True,
)
app.add_typer(doctor_app, name="doctor")


class ReportFormat(StrEnum):
    """Report formats supported by the local vertical slice."""

    TERMINAL = "terminal"
    JSON = "json"


@app.callback()
def main() -> None:
    """Verify security controls for cloud-hosted AI systems."""


@app.command()
def version() -> None:
    """Print the installed cai-verify version."""
    typer.echo(__version__)


@doctor_app.command("aws")
def doctor_aws(
    suite_path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    report: Annotated[ReportFormat, typer.Option("--report")] = ReportFormat.TERMINAL,
) -> None:
    """Check declared AWS identities with read-only STS calls."""
    try:
        suite = load_suite(suite_path)
        result = run_aws_doctor(suite, environment=os.environ)
    except Exception:  # noqa: BLE001 - public diagnostics must remain redacted.
        typer.echo("AWS doctor failed", err=True)
        raise typer.Exit(code=int(CliExitCode.EXECUTION_ERROR)) from None
    content = (
        result.to_json_bytes()
        if report is ReportFormat.JSON
        else result.to_terminal_bytes()
    )
    typer.echo(content.decode(), nl=False)
    if not result.ready:
        raise typer.Exit(code=int(CliExitCode.EXECUTION_ERROR))


@doctor_app.command("retrieval")
def doctor_retrieval(
    suite_path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    report: Annotated[ReportFormat, typer.Option("--report")] = ReportFormat.TERMINAL,
) -> None:
    """Check whether retrieval-boundary chains are ready to be attempted."""
    try:
        suite = load_suite(suite_path)
        result = run_retrieval_doctor(suite, environment=os.environ)
    except Exception:  # noqa: BLE001 - public diagnostics must remain redacted.
        typer.echo("retrieval doctor failed", err=True)
        raise typer.Exit(code=int(CliExitCode.EXECUTION_ERROR)) from None
    content = (
        result.to_json_bytes()
        if report is ReportFormat.JSON
        else result.to_terminal_bytes()
    )
    typer.echo(content.decode(), nl=False)
    if not result.ready:
        raise typer.Exit(code=int(CliExitCode.EXECUTION_ERROR))


@app.command("run-local")
def run_local(
    suite_path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    mode: Annotated[SyntheticTelemetryMode, typer.Option("--mode")],
    run_id: Annotated[str, typer.Option("--run-id")],
    evidence_root: Annotated[
        Path,
        typer.Option("--evidence-root", file_okay=False, resolve_path=True),
    ] = Path(".cai-verify/runs"),
    report: Annotated[ReportFormat, typer.Option("--report")] = ReportFormat.TERMINAL,
) -> None:
    """Run a strict JSON suite against the loopback synthetic application."""
    try:
        suite = load_suite(suite_path)
        result = run_local_suite(
            suite,
            LocalRunOptions(
                mode=mode,
                evidence_root=evidence_root,
                run_id=run_id,
            ),
        )
    except Exception:  # noqa: BLE001 - public diagnostics must remain redacted.
        typer.echo("local run failed", err=True)
        raise typer.Exit(code=2) from None
    content = (
        result.json_report if report is ReportFormat.JSON else result.terminal_report
    )
    typer.echo(content.decode(), nl=False)
    if result.exit_code:
        raise typer.Exit(code=int(result.exit_code))


@app.command("run-aws-retrieval")
def run_aws_retrieval(
    suite_path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    assertion_id: Annotated[str, typer.Option("--assertion-id")],
    run_id: Annotated[str, typer.Option("--run-id")],
    report: Annotated[ReportFormat, typer.Option("--report")] = ReportFormat.TERMINAL,
) -> None:
    """Run one pre-seeded AWS retrieval-boundary chain."""
    try:
        suite = load_suite(suite_path)
        result = run_aws_retrieval_chain(
            suite,
            AwsRetrievalRunOptions(
                run_id=run_id,
                assertion_id=assertion_id,
                environment=os.environ,
            ),
        )
    except Exception:  # noqa: BLE001 - public diagnostics must remain redacted.
        typer.echo("AWS retrieval run failed", err=True)
        raise typer.Exit(code=int(CliExitCode.EXECUTION_ERROR)) from None
    content = (
        result.json_report if report is ReportFormat.JSON else result.terminal_report
    )
    typer.echo(content.decode(), nl=False)
    if result.exit_code:
        raise typer.Exit(code=int(result.exit_code))


@app.command("verify-evidence")
def verify_evidence(
    run_directory: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            resolve_path=True,
        ),
    ],
    report: Annotated[ReportFormat, typer.Option("--report")] = ReportFormat.TERMINAL,
) -> None:
    """Verify a finalized evidence run without network or target access."""
    verification = verify_run_integrity(run_directory)
    payload = {
        "artifacts_checked": verification.artifacts_checked,
        "issues": [
            {"code": issue.code.value, "path": issue.path}
            for issue in verification.issues
        ],
        "manifest_sha256": verification.manifest_sha256,
        "run_id": verification.run_id,
        "schema_version": "1",
        "valid": verification.valid,
    }
    if report is ReportFormat.JSON:
        typer.echo(
            json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ),
        )
    else:
        state = "VALID" if verification.valid else "INVALID"
        typer.echo(f"Evidence: {state}")
        typer.echo(f"Run: {verification.run_id or '-'}")
        typer.echo(f"Artifacts checked: {verification.artifacts_checked}")
        for issue in verification.issues:
            suffix = f" ({issue.path})" if issue.path is not None else ""
            typer.echo(f"[{issue.code.value}]{suffix}")
    if not verification.valid:
        raise typer.Exit(code=2)
