"""p11test info command — show module information."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

console = Console(stderr=True)


def info_command(
    module: Path = typer.Option(..., "--module", "-m", help="Path to PKCS#11 module"),
) -> None:
    """Show PKCS#11 module information: version, slots, mechanisms."""
    if not module.exists():
        console.print(f"[red]Error:[/red] Module not found: {module}")
        raise typer.Exit(code=3)

    console.print(f"Module: {module}")
    console.print("[yellow]Info display not yet implemented[/yellow]")
    raise typer.Exit(code=0)
