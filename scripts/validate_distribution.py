"""Validate that the built wheel installs and exposes the expected CLI."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIST_DIRECTORY = PROJECT_ROOT / "dist"
COMMAND_TIMEOUT_SECONDS = 60
_SCHEMA_FILENAMES = (
    "aws-execution-policy-1alpha1.schema.json",
    "verification-suite-1alpha1.schema.json",
)
_AWS_EXAMPLE_FILENAMES = (
    "README.md",
    "reciprocal-retrieval-policy.json",
    "reciprocal-retrieval-suite.json",
)


def _only_artifact(pattern: str) -> Path:
    artifacts = sorted(DIST_DIRECTORY.glob(pattern))
    if len(artifacts) != 1:
        message = f"expected one {pattern} artifact, found {len(artifacts)}"
        raise RuntimeError(message)
    return artifacts[0].resolve(strict=True)


def main() -> None:  # noqa: C901, PLR0915 - one linear release-gate inventory.
    """Inspect distributions and smoke-test base and AWS-extra installations."""
    wheel = _only_artifact("*.whl")
    source_distribution = _only_artifact("*.tar.gz")
    _validate_inventory(wheel, source_distribution)
    uv = shutil.which("uv")
    if uv is None:
        msg = "uv is required to validate the built wheel"
        raise RuntimeError(msg)

    project = tomllib.loads(
        (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    project_metadata = project.get("project")
    if not isinstance(project_metadata, dict):
        msg = "pyproject.toml has no project table"
        raise TypeError(msg)
    expected_version = project_metadata.get("version")
    if not isinstance(expected_version, str):
        msg = "pyproject.toml has no string project version"
        raise TypeError(msg)
    command_prefix = [
        uv,
        "run",
        "--isolated",
        "--no-project",
        "--with",
        str(wheel),
    ]
    command = [*command_prefix, "cai-verify", "version"]
    # Every argument is constructed locally and the command never uses a shell.
    result = subprocess.run(  # noqa: S603
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        message = f"wheel smoke test failed:\n{result.stderr.strip()}"
        raise RuntimeError(message)
    if result.stdout.strip() != expected_version:
        message = (
            "wheel reported an unexpected version: "
            f"{result.stdout.strip()!r} != {expected_version!r}"
        )
        raise RuntimeError(message)

    root_help = _run(
        [*command_prefix, "cai-verify", "--help"],
        label="base-wheel root help",
    )
    if b"run-aws-reciprocal-retrieval" not in root_help.stdout:
        message = "base wheel help omitted the reciprocal AWS command"
        raise RuntimeError(message)

    doctor_help = _run(
        [*command_prefix, "cai-verify", "doctor", "aws", "--help"],
        label="base-wheel AWS doctor help",
    )
    if b"read-only STS" not in doctor_help.stdout:
        message = "AWS doctor help did not describe its read-only boundary"
        raise RuntimeError(message)
    if b"--execution-policy" not in doctor_help.stdout:
        message = "AWS doctor help omitted the required execution policy"
        raise RuntimeError(message)

    for command_name, filename in (
        ("suite", "verification-suite-1alpha1.schema.json"),
        ("aws-execution-policy", "aws-execution-policy-1alpha1.schema.json"),
    ):
        schema = _run(
            [*command_prefix, "cai-verify", "schema", command_name],
            label=f"base-wheel {command_name} schema",
        )
        expected = (PROJECT_ROOT / "schemas" / filename).read_bytes()
        if schema.stdout != expected:
            message = f"installed {command_name} schema bytes do not match"
            raise RuntimeError(message)

    no_boto = _run(
        [
            *command_prefix,
            "python",
            "-c",
            (
                "import importlib.util; "
                "assert importlib.util.find_spec('boto3') is None; "
                "import cai_verify.cli"
            ),
        ],
        label="base-wheel import without Boto3",
    )
    if no_boto.stdout:
        message = "base-wheel import emitted unexpected output"
        raise RuntimeError(message)

    aws_environment = {
        key: value for key, value in os.environ.items() if not key.startswith("AWS_")
    }
    aws_environment.update(
        {
            "AWS_CONFIG_FILE": os.devnull,
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
        }
    )
    aws_requirement = f"cai-verify[aws] @ {wheel.as_uri()}"
    aws_import = _run(
        [
            uv,
            "run",
            "--isolated",
            "--no-project",
            "--with",
            aws_requirement,
            "python",
            "-c",
            (
                "import socket; "
                "from unittest.mock import patch; "
                "deny = RuntimeError('network access during import'); "
                "patch.object(socket, 'socket', side_effect=deny).start(); "
                "patch.object(socket, 'create_connection', side_effect=deny).start(); "
                "patch.object(socket, 'getaddrinfo', side_effect=deny).start(); "
                "from cai_verify.aws import run_aws_reciprocal_retrieval; "
                "assert run_aws_reciprocal_retrieval.__name__ == "
                "'run_aws_reciprocal_retrieval'"
            ),
        ],
        label="AWS-extra runner import",
        environment=aws_environment,
    )
    if aws_import.stdout:
        message = "AWS-extra import emitted unexpected output"
        raise RuntimeError(message)

    sys.stdout.write(
        "Distribution validation passed: "
        f"cai-verify {expected_version}, schemas, base wheel, AWS extra, sdist\n"
    )


def _validate_inventory(wheel: Path, source_distribution: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = set(archive.namelist())
    for filename in _SCHEMA_FILENAMES:
        if f"cai_verify/schemas/{filename}" not in wheel_names:
            message = f"wheel omitted packaged schema {filename}"
            raise RuntimeError(message)

    with tarfile.open(source_distribution, mode="r:gz") as archive:
        source_names = set(archive.getnames())
    for filename in _SCHEMA_FILENAMES:
        if not any(name.endswith(f"/schemas/{filename}") for name in source_names):
            message = f"source distribution omitted schema {filename}"
            raise RuntimeError(message)
    for filename in _AWS_EXAMPLE_FILENAMES:
        if not any(name.endswith(f"/examples/aws/{filename}") for name in source_names):
            message = f"source distribution omitted AWS example {filename}"
            raise RuntimeError(message)


def _run(
    command: list[str],
    *,
    label: str,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(  # noqa: S603
        command,
        check=False,
        capture_output=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
        env=environment,
    )
    if result.returncode != 0:
        message = f"{label} failed"
        raise RuntimeError(message)
    return result


if __name__ == "__main__":
    main()
