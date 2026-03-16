"""p11test CLI application."""

from __future__ import annotations

import typer

app = typer.Typer(
    name="p11test",
    help="CLI-first PKCS#11 test suite with segfault survival and interface forcing.",
    no_args_is_help=True,
    invoke_without_command=True,
)


@app.callback()
def callback() -> None:
    """CLI-first PKCS#11 test suite."""


@app.command()
def version() -> None:
    """Show p11test version."""
    from p11test import __version__

    typer.echo(f"p11test {__version__}")


def main() -> None:
    app()
