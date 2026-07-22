"""Tests for the command-line interface."""

from typer.testing import CliRunner

from cai_verify import __version__
from cai_verify.cli import app

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
    assert "version" in result.stdout
