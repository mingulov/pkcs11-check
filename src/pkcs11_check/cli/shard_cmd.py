"""pkcs11-check shard-units / merge-shards — multi-container parallel sharding.

These two commands enable PKCS#11-safe parallelism: split the test files into N
balanced shards, run each shard in its own container (its own server+token, one
serial process — never concurrent same-token access), then merge the N artifact
directories back into one combined result set. See docs/server-pool-design-*.md.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from pkcs11_check.core.merge import merge_shard_dirs
from pkcs11_check.core.sharding import duration_by_unit_from_results, plan_shards

console = Console()

_DEFAULT_TESTCASES = "src/pkcs11_check/testcases"


def shard_units_command(
    shards: int = typer.Option(..., "--shards", "-n", help="Number of shards (>=1)"),
    testcases_dir: Path = typer.Option(
        Path(_DEFAULT_TESTCASES), "--testcases", help="Directory of test files to shard"
    ),
    prior_results: Path | None = typer.Option(
        None,
        "--prior-results",
        help="A prior results.json; per-file durations balance shards (LPT)",
    ),
    output_format: str = typer.Option(
        "lines", "--format", help="Output: 'lines' (one shard/line) or 'json'"
    ),
) -> None:
    """Plan N balanced shards of test FILES (heavy files spread via LPT).

    With ``--format lines`` (default) prints one shard per line as a
    space-separated file list — consumable by a shell launcher. With ``json``
    prints ``{"shards": [[files...], ...]}``.
    """
    if shards < 1:
        console.print("[red]Error:[/red] --shards must be >= 1")
        raise typer.Exit(code=2)

    units = sorted(str(p) for p in testcases_dir.rglob("test_*.py"))
    if not units:
        console.print(f"[red]Error:[/red] no test_*.py files under {testcases_dir}")
        raise typer.Exit(code=2)

    durations = None
    if prior_results is not None and prior_results.exists():
        durations = duration_by_unit_from_results(prior_results)

    groups = plan_shards(units, shards, duration_by_unit=durations)

    if output_format == "json":
        typer.echo(json.dumps({"shards": groups}))
    else:
        for group in groups:
            typer.echo(" ".join(group))


def merge_shards_command(
    shard_dirs: list[Path] = typer.Argument(
        ..., help="Shard artifact directories (each with results.json + report.jsonl)"
    ),
    output: Path = typer.Option(..., "--output", "-o", help="Combined output directory"),
) -> None:
    """Merge N shard artifact directories into one combined result set."""
    existing = [
        d for d in shard_dirs if (d / "results.json").exists() or (d / "report.jsonl").exists()
    ]
    if not existing:
        console.print("[red]Error:[/red] no shard dirs with results.json/report.jsonl found")
        raise typer.Exit(code=2)

    merged = merge_shard_dirs(existing, output)
    summary = merged.get("summary", {})
    console.print(
        f"[green]Merged[/green] {len(existing)} shards -> {output}  "
        f"total={summary.get('total', 0)} "
        f"passed={summary.get('passed', 0)} failed={summary.get('failed', 0)} "
        f"crashed={summary.get('crashed', 0)} timeout={summary.get('timeout', 0)}"
    )
