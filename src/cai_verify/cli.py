"""Command-line interface for Cloud AI Control Verifier."""

import typer

from cai_verify import __version__

app = typer.Typer(
    add_completion=False,
    help="Verify security controls for cloud-hosted AI systems.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """Verify security controls for cloud-hosted AI systems."""


@app.command()
def version() -> None:
    """Print the installed cai-verify version."""
    typer.echo(__version__)
