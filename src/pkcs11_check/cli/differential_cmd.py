"""pkcs11-check differential - N-way cross-provider agreement check on KAT vectors.

Loads several providers' report.jsonl artifacts and flags node-ids where the providers
that ran a deterministic known-answer vector disagree on the verdict - the odd-one-out is
a suspect (wrong crypto, a spurious rejection, or a crash). Restricted to KAT suites by
default (the sound target); pass --all to include every node-id.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from pkcs11_check.core.differential import (
    ProvenanceFingerprint,
    comparable_nodeids,
    comparison_components,
    find_disagreements,
    is_kat_nodeid,
    load_provider_outcomes,
    provenance_fingerprint,
)

console = Console()
_err = Console(stderr=True)


def _parse_provider_arg(arg: str) -> tuple[str, Path]:
    """Parse and validate a NAME=report.jsonl pair or a bare report path."""
    if "=" in arg:
        name, raw = arg.split("=", 1)
    else:
        raw = arg
        name = Path(raw.strip()).stem
    name = name.strip()
    raw = raw.strip()
    if not name:
        raise ValueError("provider name must not be empty")
    if not raw:
        raise ValueError("report path must not be empty")
    try:
        path = Path(raw).expanduser().resolve()
        is_file = path.is_file()
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"cannot resolve report path {raw}: {exc}") from exc
    if not is_file:
        raise ValueError(f"report log is not a file: {path}")
    return name, path


def _iter_report_records_strict(path: Path) -> Iterator[dict[str, Any]]:
    """Yield records from one complete, structurally valid pytest report log."""
    seen_record = False
    seen_start = False
    seen_finish = False
    try:
        with path.open(encoding="utf-8") as report:
            for line_number, raw_line in enumerate(report, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"malformed report log {path}:{line_number}: {exc.msg}"
                    ) from exc
                if not isinstance(record, dict):
                    raise ValueError(
                        f"malformed report log {path}:{line_number}: expected JSON object"
                    )
                report_type = record.get("$report_type")
                if not isinstance(report_type, str) or not report_type:
                    raise ValueError(
                        f"malformed report log {path}:{line_number}: missing $report_type"
                    )
                if not seen_start and report_type != "SessionStart":
                    raise ValueError(
                        f"malformed report log {path}:{line_number}: "
                        "first record is not SessionStart"
                    )
                if report_type == "SessionStart":
                    if seen_start or seen_finish:
                        raise ValueError(
                            f"malformed report log {path}:{line_number}: duplicate SessionStart"
                        )
                    seen_start = True
                elif report_type == "SessionFinish":
                    exitstatus = record.get("exitstatus")
                    if (
                        seen_finish
                        or not isinstance(exitstatus, int)
                        or isinstance(exitstatus, bool)
                    ):
                        raise ValueError(
                            f"malformed report log {path}:{line_number}: invalid SessionFinish"
                        )
                    seen_finish = True
                elif report_type == "TestReport":
                    nodeid = record.get("nodeid")
                    when = record.get("when")
                    outcome = record.get("outcome")
                    if seen_finish or not isinstance(nodeid, str) or not nodeid.strip():
                        raise ValueError(
                            f"malformed report log {path}:{line_number}: invalid TestReport nodeid"
                        )
                    if not isinstance(when, str) or when not in {"setup", "call", "teardown"}:
                        raise ValueError(
                            f"malformed report log {path}:{line_number}: invalid TestReport phase"
                        )
                    if not isinstance(outcome, str) or outcome not in {
                        "passed",
                        "failed",
                        "skipped",
                    }:
                        raise ValueError(
                            f"malformed report log {path}:{line_number}: invalid TestReport outcome"
                        )
                seen_record = True
                yield record
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot read report log {path}: {exc}") from exc
    if not seen_record:
        raise ValueError(f"report log is empty: {path}")
    if not seen_start or not seen_finish:
        raise ValueError(f"incomplete report log (missing start/finish): {path}")


def _load_provenance(report_path: Path) -> ProvenanceFingerprint:
    try:
        results_path = report_path.with_name("results.json")
        is_file = results_path.is_file()
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"cannot read provenance beside {report_path}: {exc}") from exc
    if not is_file:
        raise ValueError(f"sibling results.json not found: {results_path}")
    try:
        payload = json.loads(results_path.read_text(encoding="utf-8"))
    except (OSError, RuntimeError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read provenance from {results_path}: {exc}") from exc
    if not isinstance(payload, dict) or (fingerprint := provenance_fingerprint(payload)) is None:
        raise ValueError(f"incomplete framework/test-data provenance: {results_path}")
    return fingerprint


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
    allow_unverified_provenance: bool = typer.Option(
        False,
        "--allow-unverified-provenance",
        help="Compare despite missing/mismatched sibling results.json provenance (warns)",
    ),
) -> None:
    """Diff N providers' KAT verdicts and report the odd-one-out per disagreeing node-id."""
    if len(providers) < 2:
        _err.print("[red]Error:[/red] need at least two providers to compare")
        raise typer.Exit(code=2)

    parsed_inputs: list[tuple[str, Path]] = []
    seen_names: set[str] = set()
    seen_paths: set[Path] = set()
    for arg in providers:
        try:
            name, path = _parse_provider_arg(arg)
        except ValueError as exc:
            _err.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=2) from exc
        if name in seen_names:
            _err.print(f"[red]Error:[/red] duplicate provider name: {name}")
            raise typer.Exit(code=2)
        if path in seen_paths:
            _err.print(f"[red]Error:[/red] duplicate report path: {path}")
            raise typer.Exit(code=2)
        seen_names.add(name)
        seen_paths.add(path)
        parsed_inputs.append((name, path))

    if min_providers < 2:
        _err.print("[red]Error:[/red] --min-providers must be at least 2")
        raise typer.Exit(code=2)
    if min_providers > len(parsed_inputs):
        _err.print(
            f"[red]Error:[/red] --min-providers {min_providers} exceeds "
            f"{len(parsed_inputs)} unique provider inputs"
        )
        raise typer.Exit(code=2)

    per_provider: dict[str, dict[str, str]] = {}
    for name, path in parsed_inputs:
        try:
            outcomes = load_provider_outcomes(_iter_report_records_strict(path))
            if not outcomes:
                raise ValueError(f"report log contains no test outcomes: {path}")
        except ValueError as exc:
            _err.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=2) from exc
        per_provider[name] = outcomes

    if allow_unverified_provenance:
        _err.print("[yellow]WARNING: provenance verification disabled[/yellow]")
    else:
        try:
            fingerprints = {_load_provenance(path) for _, path in parsed_inputs}
        except ValueError as exc:
            _err.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=2) from exc
        if len(fingerprints) != 1:
            _err.print(
                "[red]Error:[/red] incompatible framework/test-data provenance across providers"
            )
            raise typer.Exit(code=2)

    nodeid_filter = None
    if not include_all:
        kat = {n for outs in per_provider.values() for n in outs if is_kat_nodeid(n)}
        nodeid_filter = frozenset(kat)

    comparable = comparable_nodeids(
        per_provider, min_providers=min_providers, nodeid_filter=nodeid_filter
    )
    scope = "node-ids" if include_all else "deterministic KAT node-ids"
    if not comparable:
        _err.print(f"[red]Error:[/red] no comparable {scope} across provider inputs")
        raise typer.Exit(code=2)
    components = comparison_components(per_provider, nodeids=comparable)
    if len(components) != 1:
        groups = " | ".join(",".join(sorted(component)) for component in components)
        _err.print(f"[red]Error:[/red] provider evidence is disconnected: {groups}")
        raise typer.Exit(code=2)

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
    _err.print(
        f"[dim]{len(disagreements)} disagreement(s) across {len(per_provider)} providers; "
        f"{len(comparable)} comparable {scope}[/dim]"
    )
    if disagreements:
        raise typer.Exit(code=1)
