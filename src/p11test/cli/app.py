"""p11test CLI application."""

from __future__ import annotations

import typer

from p11test.cli.info_cmd import info_command
from p11test.cli.list_cmd import list_command
from p11test.cli.test_cmd import test_command

app = typer.Typer(
    name="p11test",
    help="CLI-first PKCS#11 test suite with segfault survival and interface forcing.",
    no_args_is_help=True,
    invoke_without_command=True,
)


@app.callback()
def callback() -> None:
    """CLI-first PKCS#11 test suite."""


app.command("test")(test_command)
app.command("info")(info_command)
app.command("list")(list_command)


@app.command()
def version() -> None:
    """Show p11test version."""
    from p11test import __version__

    typer.echo(f"p11test {__version__}")


def main() -> None:
    app()
