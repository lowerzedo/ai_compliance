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
_REFERENCE_TARGET_FILENAMES = (
    "README.md",
    "__init__.py",
    "config.py",
    "handler.py",
    "manager.py",
    "template.json",
)
_REFERENCE_TARGET_PARENT_FILES = (
    "examples/__init__.py",
    "examples/aws/__init__.py",
)
_README_SCREENSHOT_FILENAMES = (
    "console-evidence-history.jpg",
    "console-plan-review.jpg",
)
_UI_GENERATED_DIRECTORIES = ("dist", "node_modules")
_UI_STATIC_DIRECTORY = PROJECT_ROOT / "src/cai_verify/ui/static"


def _only_artifact(pattern: str) -> Path:
    artifacts = sorted(DIST_DIRECTORY.glob(pattern))
    if len(artifacts) != 1:
        message = f"expected one {pattern} artifact, found {len(artifacts)}"
        raise RuntimeError(message)
    return artifacts[0].resolve(strict=True)


def main() -> None:  # noqa: C901, PLR0912, PLR0915 - linear release inventory.
    """Inspect distributions and smoke-test base, AWS, and UI installations."""
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

    ui_requirement = f"cai-verify[ui] @ {wheel.as_uri()}"
    ui_import = _run(
        [
            uv,
            "run",
            "--isolated",
            "--no-project",
            "--with",
            ui_requirement,
            "python",
            "-c",
            (
                "from importlib.resources import files; "
                "from cai_verify.ui import create_console_app; "
                "asset = files('cai_verify.ui').joinpath('static/index.html'); "
                "assert asset.is_file(); "
                "assert callable(create_console_app)"
            ),
        ],
        label="UI-extra packaged-asset import",
    )
    if ui_import.stdout:
        message = "UI-extra import emitted unexpected output"
        raise RuntimeError(message)

    combined_requirement = f"cai-verify[aws,ui] @ {wheel.as_uri()}"
    combined_help = _run(
        [
            uv,
            "run",
            "--isolated",
            "--no-project",
            "--with",
            combined_requirement,
            "cai-verify",
            "ui",
            "--help",
        ],
        label="combined AWS-and-UI operator help",
        environment=aws_environment,
    )
    if not all(
        option in combined_help.stdout
        for option in (b"--evidence-root", b"--port", b"--no-open")
    ):
        message = "combined AWS-and-UI install omitted console launch options"
        raise RuntimeError(message)

    sys.stdout.write(
        "Distribution validation passed: "
        f"cai-verify {expected_version}, schemas, UI assets, "
        "base wheel, AWS extra, UI extra, combined operator install, sdist\n"
    )


def _validate_inventory(  # noqa: C901, PLR0912 - explicit archive checks stay visible.
    wheel: Path,
    source_distribution: Path,
) -> None:
    ui_assets = _ui_asset_inventory()
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = set(archive.namelist())
        if any(
            name.startswith("examples/") or "/examples/aws/reference_target/" in name
            for name in wheel_names
        ):
            message = "wheel included source-only reference-target files"
            raise RuntimeError(message)
        for relative_path, expected in ui_assets.items():
            archive_path = f"cai_verify/ui/static/{relative_path}"
            if archive_path not in wheel_names:
                message = f"wheel omitted packaged UI asset {relative_path}"
                raise RuntimeError(message)
            if archive.read(archive_path) != expected:
                message = f"wheel UI asset differs from source {relative_path}"
                raise RuntimeError(message)
    for filename in _SCHEMA_FILENAMES:
        if f"cai_verify/schemas/{filename}" not in wheel_names:
            message = f"wheel omitted packaged schema {filename}"
            raise RuntimeError(message)

    with tarfile.open(source_distribution, mode="r:gz") as archive:
        source_names = set(archive.getnames())
        if any(
            "/ui/node_modules/" in name or "/ui/dist/" in name for name in source_names
        ):
            message = "source distribution included generated frontend directories"
            raise RuntimeError(message)
        for relative_path, expected in ui_assets.items():
            suffix = f"/src/cai_verify/ui/static/{relative_path}"
            matches = [name for name in source_names if name.endswith(suffix)]
            if len(matches) != 1:
                message = (
                    "source distribution omitted or duplicated UI asset "
                    f"{relative_path}"
                )
                raise RuntimeError(message)
            extracted = archive.extractfile(matches[0])
            if extracted is None or extracted.read() != expected:
                message = (
                    f"source distribution UI asset differs from source {relative_path}"
                )
                raise RuntimeError(message)
        for filename in _SCHEMA_FILENAMES:
            if not any(name.endswith(f"/schemas/{filename}") for name in source_names):
                message = f"source distribution omitted schema {filename}"
                raise RuntimeError(message)
        for filename in _AWS_EXAMPLE_FILENAMES:
            if not any(
                name.endswith(f"/examples/aws/{filename}") for name in source_names
            ):
                message = f"source distribution omitted AWS example {filename}"
                raise RuntimeError(message)
        _validate_readme_screenshot_inventory(archive, source_names)
        _validate_reference_target_inventory(archive, source_names)
        for relative_path, expected in _ui_source_inventory().items():
            suffix = f"/ui/{relative_path}"
            matches = [name for name in source_names if name.endswith(suffix)]
            if len(matches) != 1:
                message = (
                    "source distribution omitted or duplicated front-end source "
                    f"{relative_path}"
                )
                raise RuntimeError(message)
            extracted = archive.extractfile(matches[0])
            if extracted is None or extracted.read() != expected:
                message = (
                    "source distribution front-end source differs from source "
                    f"{relative_path}"
                )
                raise RuntimeError(message)


def _validate_readme_screenshot_inventory(
    archive: tarfile.TarFile,
    source_names: set[str],
) -> None:
    """Require the README's repository screenshots in the source archive."""
    for filename in _README_SCREENSHOT_FILENAMES:
        expected = PROJECT_ROOT / "assets" / "screenshots" / filename
        matches = [
            name
            for name in source_names
            if name.endswith(f"/assets/screenshots/{filename}")
        ]
        if len(matches) != 1:
            message = f"source distribution omitted README screenshot {filename}"
            raise RuntimeError(message)
        extracted = archive.extractfile(matches[0])
        if extracted is None or extracted.read() != expected.read_bytes():
            message = (
                f"source distribution README screenshot differs from source {filename}"
            )
            raise RuntimeError(message)


def _validate_reference_target_inventory(
    archive: tarfile.TarFile,
    source_names: set[str],
) -> None:
    reference_root = PROJECT_ROOT / "examples/aws/reference_target"
    expected_sources = {
        f"examples/aws/reference_target/{filename}": reference_root / filename
        for filename in _REFERENCE_TARGET_FILENAMES
    }
    expected_sources.update(
        {
            relative_path: PROJECT_ROOT / relative_path
            for relative_path in _REFERENCE_TARGET_PARENT_FILES
        }
    )
    for relative_path, expected_path in expected_sources.items():
        suffix = f"/{relative_path}"
        matches = [name for name in source_names if name.endswith(suffix)]
        if len(matches) != 1:
            message = (
                "source distribution omitted or duplicated reference target "
                f"{relative_path}"
            )
            raise RuntimeError(message)
        member = archive.getmember(matches[0])
        extracted = archive.extractfile(member)
        if (
            not member.isfile()
            or extracted is None
            or extracted.read() != expected_path.read_bytes()
        ):
            message = (
                f"source distribution reference target differs for {relative_path}"
            )
            raise RuntimeError(message)
    expected_reference_suffixes = {
        f"/examples/aws/reference_target/{filename}"
        for filename in _REFERENCE_TARGET_FILENAMES
    }
    observed_reference_names = {
        name for name in source_names if "/examples/aws/reference_target/" in name
    }
    if any(
        not any(name.endswith(suffix) for suffix in expected_reference_suffixes)
        for name in observed_reference_names
    ):
        message = "source distribution included unapproved reference-target state"
        raise RuntimeError(message)


def _ui_asset_inventory() -> dict[str, bytes]:
    if not _UI_STATIC_DIRECTORY.is_dir():
        message = "packaged UI asset directory is unavailable"
        raise RuntimeError(message)
    inventory = {
        path.relative_to(_UI_STATIC_DIRECTORY).as_posix(): path.read_bytes()
        for path in sorted(_UI_STATIC_DIRECTORY.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }
    if "index.html" not in inventory or any(
        path.endswith(".map") for path in inventory
    ):
        message = "packaged UI asset inventory is invalid"
        raise RuntimeError(message)
    return inventory


def _ui_source_inventory() -> dict[str, bytes]:
    source_root = PROJECT_ROOT / "ui"
    if not source_root.is_dir():
        message = "front-end source directory is unavailable"
        raise RuntimeError(message)
    return {
        path.relative_to(source_root).as_posix(): path.read_bytes()
        for path in sorted(source_root.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and not path.name.startswith(".")
        and not any(
            part in _UI_GENERATED_DIRECTORIES
            for part in path.relative_to(source_root).parts
        )
    }


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
