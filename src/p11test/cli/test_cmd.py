"""p11test test command — run PKCS#11 test suite."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

console = Console(stderr=True)


def test_command(
    module: Path = typer.Option(..., "--module", "-m", help="Path to PKCS#11 module"),
    interface: str = typer.Option("auto", "--interface", "-i", help="Interface version"),
    sessions: int = typer.Option(1, "--sessions", "-s", help="Concurrent sessions"),
    timeout: int = typer.Option(120, "--timeout", "-t", help="Per-test timeout (seconds)"),
    category: str | None = typer.Option(None, "--category", "-c", help="Test categories"),
    match: str | None = typer.Option(None, "--match", help="Test name pattern"),
    destructive: bool = typer.Option(False, "--destructive", help="Enable destructive tests"),
    output: str = typer.Option("rich", "--output", "-o", help="Output format: rich, json, junit"),
) -> None:
    """Run the PKCS#11 test suite against a module."""
    if not module.exists():
        console.print(f"[red]Error:[/red] Module not found: {module}")
        raise typer.Exit(code=3)

    console.print(f"Loading module: {module}")
    console.print(f"Interface: {interface}")
    console.print("[yellow]Test execution not yet implemented[/yellow]")
    raise typer.Exit(code=0)
