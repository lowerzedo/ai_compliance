"""Validate that the built wheel installs and exposes the expected CLI."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIST_DIRECTORY = PROJECT_ROOT / "dist"
COMMAND_TIMEOUT_SECONDS = 60


def _only_artifact(pattern: str) -> Path:
    artifacts = sorted(DIST_DIRECTORY.glob(pattern))
    if len(artifacts) != 1:
        message = f"expected one {pattern} artifact, found {len(artifacts)}"
        raise RuntimeError(message)
    return artifacts[0].resolve(strict=True)


def main() -> None:
    """Install the wheel in isolation and check its console entry point."""
    wheel = _only_artifact("*.whl")
    _only_artifact("*.tar.gz")
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
    command = [
        uv,
        "run",
        "--isolated",
        "--no-project",
        "--with",
        str(wheel),
        "cai-verify",
        "version",
    ]
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

    doctor_help = subprocess.run(  # noqa: S603
        [*command[:-1], "doctor", "aws", "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    if doctor_help.returncode != 0:
        message = (
            "base wheel could not load AWS doctor help without the optional SDK:\n"
            f"{doctor_help.stderr.strip()}"
        )
        raise RuntimeError(message)
    if "read-only STS" not in doctor_help.stdout:
        message = "AWS doctor help did not describe its read-only boundary"
        raise RuntimeError(message)

    sys.stdout.write(
        "Wheel CLI smoke tests passed: "
        f"cai-verify {expected_version}, AWS doctor help\n"
    )


if __name__ == "__main__":
    main()
