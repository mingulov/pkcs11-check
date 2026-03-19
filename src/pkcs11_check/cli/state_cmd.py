"""pkcs11-check state command — inspect isolated runner state and policy files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from pkcs11_check.core.file_runner import load_isolation_policy, load_run_state, state_results_by_status

console = Console()


def _load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text())
    if not isinstance(raw, dict):
        msg = f"Unsupported state file structure: {path}"
        raise ValueError(msg)
    return raw


def _render_state_file(path: Path) -> None:
    state = load_run_state(path)
    if state is None:
        console.print(f"[red]Error:[/red] State file not found: {path}")
        raise typer.Exit(code=2)

    counts = state_results_by_status(path)
    console.print(f"[bold]State File:[/bold] {path}")
    console.print(f"[bold]Units:[/bold] {len(state.units)}")
    console.print(f"[bold]Results:[/bold] {len(state.results)}")
    console.print(f"[bold]Fingerprint:[/bold] {state.fingerprint}")

    summary = Table(title="Status Summary")
    summary.add_column("Status", style="cyan")
    summary.add_column("Count", justify="right")
    for status, count in sorted(counts.items()):
        summary.add_row(status, str(count))
    console.print(summary)

    interesting = [result for result in state.results if result.status not in {"passed", "empty"}]
    if interesting:
        details = Table(title="Interesting Units")
        details.add_column("Target", style="cyan")
        details.add_column("Status")
        details.add_column("Seconds", justify="right")
        for result in interesting:
            details.add_row(result.target, result.status, f"{result.duration_s:.1f}")
        console.print(details)


def _render_policy_file(path: Path) -> None:
    policies = load_isolation_policy(path)
    console.print(f"[bold]Policy File:[/bold] {path}")
    console.print(f"[bold]Backends:[/bold] {len(policies)}")

    table = Table(title="Backend Policies")
    table.add_column("Fingerprint", style="cyan")
    table.add_column("Promoted Files", justify="right")
    table.add_column("Crashing Tests", justify="right")
    for fingerprint, policy in sorted(policies.items()):
        table.add_row(
            fingerprint[:12],
            str(len(policy.promoted_files)),
            str(len(policy.crashed_tests)),
        )
    console.print(table)


def state_command(
    path: Path = typer.Argument(..., help="Path to an isolation state or policy JSON file"),
    output: str = typer.Option("rich", "--output", "-o", help="Output: rich, json"),
) -> None:
    """Inspect isolated runner state and adaptive policy files."""
    if not path.exists():
        console.print(f"[red]Error:[/red] File not found: {path}")
        raise typer.Exit(code=2)

    if output == "json":
        console.print_json(path.read_text())
        return

    if output != "rich":
        console.print(f"[red]Error:[/red] Unsupported output format: {output}")
        raise typer.Exit(code=2)

    data = _load_json(path)
    if "results" in data and "units" in data:
        _render_state_file(path)
        return
    if "backends" in data:
        _render_policy_file(path)
        return

    console.print(f"[red]Error:[/red] Unrecognized file type: {path}")
    raise typer.Exit(code=2)
