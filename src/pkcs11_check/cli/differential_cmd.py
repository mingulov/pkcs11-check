"""pkcs11-check differential - N-way cross-provider agreement check on KAT vectors.

Loads several providers' report.jsonl artifacts and flags node-ids where the providers
that ran a deterministic known-answer vector disagree on the verdict - the odd-one-out is
a suspect (wrong crypto, a spurious rejection, or a crash). Restricted to KAT suites by
default (the sound target); pass --all to include every node-id.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from pkcs11_check.core.differential import (
    find_disagreements,
    is_kat_nodeid,
    load_provider_outcomes,
)
from pkcs11_check.core.report_log import iter_report_log_records

console = Console()
_err = Console(stderr=True)


def _parse_provider_arg(arg: str) -> tuple[str, Path]:
    """Parse a NAME=path.jsonl pair (or a bare path, named by its stem)."""
    if "=" in arg:
        name, _, raw = arg.partition("=")
        return name or Path(raw).stem, Path(raw)
    return Path(arg).stem, Path(arg)


def differential_command(
    providers: list[str] = typer.Argument(  # noqa: B008
        ..., help="Provider report logs as NAME=report.jsonl (>= 2)"
    ),
    include_all: bool = typer.Option(
        False, "--all", help="Compare every node-id, not only deterministic KAT suites"
    ),
    min_providers: int = typer.Option(
        2, "--min-providers", help="Min providers that must have run a node-id to compare it"
    ),
) -> None:
    """Diff N providers' KAT verdicts and report the odd-one-out per disagreeing node-id."""
    if len(providers) < 2:
        _err.print("[red]Error:[/red] need at least two providers to compare")
        raise typer.Exit(code=2)

    per_provider: dict[str, dict[str, str]] = {}
    for arg in providers:
        name, path = _parse_provider_arg(arg)
        if not path.exists():
            _err.print(f"[red]Error:[/red] report log not found: {path}")
            raise typer.Exit(code=2)
        per_provider[name] = load_provider_outcomes(iter_report_log_records(path))

    nodeid_filter = None
    if not include_all:
        kat = {n for outs in per_provider.values() for n in outs if is_kat_nodeid(n)}
        nodeid_filter = frozenset(kat)

    disagreements = find_disagreements(
        per_provider, min_providers=min_providers, nodeid_filter=nodeid_filter
    )

    for d in disagreements:
        verdicts = ", ".join(f"{p}={c}" for p, c in sorted(d.outcomes.items()))
        console.print(
            f"[yellow]DISAGREE[/yellow] {d.nodeid}\n"
            f"  majority={d.majority}  odd-one-out={', '.join(d.minority_providers)}\n"
            f"  verdicts: {verdicts}"
        )
    scope = "all node-ids" if include_all else "KAT suites"
    _err.print(
        f"[dim]{len(disagreements)} disagreement(s) across {len(per_provider)} providers "
        f"({scope})[/dim]"
    )
    if disagreements:
        raise typer.Exit(code=1)
