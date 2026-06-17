"""pkcs11-check compliance-report command."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

console = Console()


def compliance_report_command(
    module: Path = typer.Option(..., "--module", "-m", help="Path to PKCS#11 module"),
    interface: str = typer.Option("auto", "--interface", "-i", help="Interface version"),
    output: str = typer.Option("json", "--output", "-o", help="Output format: json|summary"),
    results: Path | None = typer.Option(None, "--results", help="JSON test results file"),
    slot: int = typer.Option(0, "--slot", "-s", help="Slot index to probe"),
) -> None:
    """Generate machine-readable PKCS#11 compliance report."""
    from pkcs11_check.compliance_report import generate_report
    from pkcs11_check.core.loader import load_module

    if not module.exists():
        console.print(f"[red]Error:[/red] Module not found: {module}")
        raise typer.Exit(code=3)

    try:
        p11 = load_module(module, interface=interface)
    except Exception as exc:
        console.print(f"[red]Error loading module:[/red] {exc}")
        raise typer.Exit(code=3) from exc

    report = generate_report(
        module_path=str(module),
        module=p11,
        test_results_path=results,
        slot_index=slot,
    )

    if output == "json":
        typer.echo(json.dumps(report, indent=2))
    elif output == "summary":
        _print_summary(report)
    else:
        console.print(f"[red]Error:[/red] Unknown output format: {output!r}")
        raise typer.Exit(code=2)


def _print_summary(report: dict[str, object]) -> None:
    """Print a rich summary of the compliance report."""
    agg: dict[str, object] = report.get("aggregate", {})  # type: ignore[assignment]

    console.print("\n[bold]PKCS#11 Compliance Report[/bold]")
    console.print(f"  Module: {report.get('module', 'unknown')}")
    console.print(f"  Interface: v{report.get('interface_version', '?')}")
    console.print(f"  Timestamp: {report.get('timestamp', '?')}")

    # Mechanism summary
    mechs_sup = agg.get("mechanisms_supported", 0)
    mechs_total = agg.get("mechanisms_total", 0)
    console.print(f"\n[bold]Mechanisms:[/bold] {mechs_sup}/{mechs_total} supported")

    mechanisms: dict[str, str] = report.get("mechanisms", {})  # type: ignore[assignment]
    mech_table = Table(show_header=True)
    mech_table.add_column("Mechanism", style="cyan")
    mech_table.add_column("Status")
    for name, status in sorted(mechanisms.items()):
        style = "green" if status == "SUPPORTED" else "dim"
        mech_table.add_row(name, f"[{style}]{status}[/{style}]")
    console.print(mech_table)

    # Function summary
    funcs_tested = agg.get("functions_tested", 0)
    funcs_total = agg.get("functions_total", 0)
    console.print(f"\n[bold]Functions:[/bold] {funcs_tested}/{funcs_total} tested")

    functions: dict[str, dict[str, object]] = report.get("functions", {})  # type: ignore[assignment]
    func_table = Table(show_header=True)
    func_table.add_column("Function", style="cyan")
    func_table.add_column("Status")
    func_table.add_column("Tests", justify="right")
    func_table.add_column("Passed", justify="right")
    func_table.add_column("Failed", justify="right")
    for name, info in functions.items():
        status = str(info.get("status", "?"))
        style_map = {
            "PASS": "green",
            "FAIL": "red",
            "ERROR": "red",
            "CRASHED": "red",
            "TIMEOUT": "red",
            "XFAIL": "yellow",
            "XPASS": "yellow",
            "SKIP": "yellow",
            "NOT_TESTED": "dim",
        }
        style = style_map.get(status, "white")
        func_table.add_row(
            name,
            f"[{style}]{status}[/{style}]",
            str(info.get("tests", 0)),
            str(info.get("passed", 0)),
            str(info.get("failed", 0)),
        )
    console.print(func_table)

    # CKR coverage
    ckr: dict[str, object] = report.get("ckr_coverage", {})  # type: ignore[assignment]
    ckr_pct = agg.get("ckr_coverage_pct", 0)
    console.print(
        f"\n[bold]CKR Coverage:[/bold] {ckr.get('tested', 0)}"
        f"/{ckr.get('total_specs', 0)} specs"
        f" ({ckr_pct}%)"
    )

    # Compliance notes
    notes: list[dict[str, str]] = report.get("compliance_notes", [])  # type: ignore[assignment]
    if notes:
        console.print(f"\n[bold]Compliance Notes:[/bold] {len(notes)}")
        for n in notes[:10]:
            console.print(f"  [{n.get('level', '?')}] {n.get('description', '')}")
        if len(notes) > 10:
            console.print(f"  ... and {len(notes) - 10} more")
