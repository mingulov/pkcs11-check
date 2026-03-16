"""p11test test command — run PKCS#11 test suite."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import typer
from rich.console import Console

console = Console(stderr=True)

_TESTCASES_DIR = str(Path(__file__).parent.parent / "testcases")


def test_command(
    module: Path = typer.Option(..., "--module", "-m", help="Path to PKCS#11 module"),
    interface: str = typer.Option("auto", "--interface", "-i", help="Interface version"),
    sessions: int = typer.Option(1, "--sessions", "-s", help="Concurrent sessions"),
    timeout: int = typer.Option(120, "--timeout", "-t", help="Per-test timeout (seconds)"),
    category: str | None = typer.Option(None, "--category", "-c", help="Test categories"),
    match: str | None = typer.Option(None, "--match", help="Test name pattern"),
    pin: str | None = typer.Option(None, "--pin", help="PIN (prefer P11TEST_PIN env)"),
    slot: int = typer.Option(0, "--slot", help="Slot index"),
    destructive: bool = typer.Option(False, "--destructive", help="Enable destructive tests"),
    output: str = typer.Option("rich", "--output", "-o", help="Output: rich, json, junit"),
    output_file: str | None = typer.Option(None, "--output-file", help="Output file path"),
    verbose: bool = typer.Option(False, "--verbose", "-V", help="Verbose output"),
) -> None:
    """Run the PKCS#11 test suite against a module."""
    if not module.exists():
        console.print(f"[red]Error:[/red] Module not found: {module}")
        raise typer.Exit(code=3)

    # Pass PIN via env so pytest fixtures pick it up
    if pin:
        os.environ["P11TEST_PIN"] = pin

    # Build pytest args
    args: list[str] = [_TESTCASES_DIR]
    args.extend(["--p11-module", str(module)])
    args.extend(["--p11-interface", interface])
    args.extend(["--p11-slot", str(slot)])

    if pin:
        args.extend(["--p11-pin", pin])

    if destructive:
        args.append("--p11-destructive")

    if match:
        args.extend(["-k", match])
    elif category:
        # Map category to test file pattern
        args.extend(["-k", category])

    if verbose:
        args.append("-v")
    else:
        args.append("-q")

    if output == "junit":
        args.extend(["--junit-xml", output_file or "p11test-results.xml"])
    elif output == "json":
        args.extend(["--tb=no", "-q"])

    args.append("--tb=short")
    args.append("--no-header")

    exit_code = pytest.main(args)
    raise typer.Exit(code=int(exit_code))
