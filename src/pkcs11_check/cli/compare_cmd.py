"""pkcs11-check compare-coverage command."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from pkcs11_check.core.quality_audit import compare_mechanism_coverage_states

console = Console()


def compare_coverage_command(
    baseline: Path = typer.Argument(
        ...,
        help="Baseline artifact directory, coverage.json, or results.json with embedded coverage",
    ),
    candidate: Path = typer.Argument(
        ...,
        help="Candidate artifact directory, coverage.json, or results.json with embedded coverage",
    ),
    output: str = typer.Option("summary", "--output", "-o", help="Output: summary|json"),
    fail_on_loss: bool = typer.Option(
        False,
        "--fail-on-loss",
        help="Exit 1 when the candidate loses any baseline mechanism coverage state",
    ),
) -> None:
    """Compare provider-local mechanism coverage states between two artifacts."""
    baseline_path, baseline_payload = _load_coverage_payload(baseline)
    candidate_path, candidate_payload = _load_coverage_payload(candidate)
    comparison = compare_mechanism_coverage_states(baseline_payload, candidate_payload)
    comparison["baseline"] = str(baseline_path)
    comparison["candidate"] = str(candidate_path)

    if output == "json":
        typer.echo(json.dumps(comparison, indent=2))
    elif output == "summary":
        _print_summary(comparison)
    else:
        console.print(f"[red]Error:[/red] Unknown output format: {output!r}")
        raise typer.Exit(code=2)

    if fail_on_loss and comparison["has_loss"]:
        raise typer.Exit(code=1)


def compare_results_command(
    baseline: Path = typer.Argument(..., help="Baseline results.json"),
    current: Path = typer.Argument(..., help="Current results.json"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show per-target detail"),
    no_fail: bool = typer.Option(False, "--no-fail", help="Report but exit 0 even on regression"),
) -> None:
    """Compare two pkcs11-check results.json files and report regressions."""
    from pkcs11_check.core.compare_results import compare_results, load_results, render_text

    for path in (baseline, current):
        if not path.exists():
            console.print(f"[red]Error:[/red] {path} not found")
            raise typer.Exit(code=2)
    try:
        base_map, base_summary = load_results(baseline)
        curr_map, curr_summary = load_results(current)
    except json.JSONDecodeError as exc:
        console.print(f"[red]Error:[/red] invalid results JSON: {exc}")
        raise typer.Exit(code=2) from exc

    comparison = compare_results(base_map, base_summary, curr_map, curr_summary)
    console.print(
        render_text(
            comparison,
            baseline_name=baseline.name,
            current_name=current.name,
            verbose=verbose,
        )
    )

    if comparison.has_regressions and not no_fail:
        raise typer.Exit(code=1)


def _load_coverage_payload(path: Path) -> tuple[Path, Mapping[str, Any]]:
    coverage_path = path / "coverage.json" if path.is_dir() else path
    if not coverage_path.exists():
        console.print(f"[red]Error:[/red] coverage artifact not found: {coverage_path}")
        raise typer.Exit(code=2)
    try:
        payload = json.loads(coverage_path.read_text())
    except json.JSONDecodeError as exc:
        console.print(f"[red]Error:[/red] invalid JSON in {coverage_path}: {exc}")
        raise typer.Exit(code=2) from exc
    if not isinstance(payload, Mapping):
        console.print(f"[red]Error:[/red] coverage artifact is not a JSON object: {coverage_path}")
        raise typer.Exit(code=2)

    embedded = payload.get("coverage")
    if isinstance(embedded, Mapping):
        return coverage_path, embedded
    if isinstance(payload.get("mechanism_coverage"), Mapping):
        return coverage_path, payload

    console.print(f"[red]Error:[/red] no mechanism_coverage found in {coverage_path}")
    raise typer.Exit(code=2)


def _print_summary(comparison: Mapping[str, Any]) -> None:
    lost_by_state = comparison.get("lost_by_state")
    if not isinstance(lost_by_state, Mapping) or not lost_by_state:
        console.print("[green]No mechanism coverage state loss[/green]")
        return

    console.print("[red]Mechanism coverage state loss detected[/red]")
    for state, names in lost_by_state.items():
        if not isinstance(names, list):
            continue
        console.print(f"  {state}: {', '.join(str(name) for name in names)}")
