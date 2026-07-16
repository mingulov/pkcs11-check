"""pkcs11-check list-tests command - enumerate node-ids matching a selection.

Prints matching pytest node-ids one per line to stdout (pipeable into a disabled-tests
file); count and diagnostics go to stderr. Collection-only: no provider run.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from pkcs11_check.cli.test_cmd import _TESTCASES_DIR, _combine_marker
from pkcs11_check.core.file_runner import collect_pytest_nodeids

_err = Console(stderr=True)


def _build_list_selection_args(
    *,
    match: str | None,
    marker: str | None,
    category: str | None,
    skip_slow: bool,
    only_slow: bool,
    module: Path | None,
    interface: str,
    slot: int,
) -> list[str]:
    """Build the pytest args for the collection subprocess (module trio + -m/-k selection)."""
    args: list[str] = []
    if module is not None:
        args += ["--p11-module", str(module), "--p11-interface", interface, "--p11-slot", str(slot)]
    combined_marker = _combine_marker(marker, skip_slow=skip_slow, only_slow=only_slow)
    if combined_marker:
        args += ["-m", combined_marker]
    if match:
        args += ["-k", match]
    elif category:
        args += ["-k", category]
    return args


def enumerate_nodeids(
    targets: list[str],
    *,
    match: str | None,
    marker: str | None,
    category: str | None,
    skip_slow: bool,
    only_slow: bool,
    module: Path | None,
    interface: str,
    slot: int,
) -> list[str]:
    """Collect node-ids matching the selection, sorted and de-duplicated.

    Empty ``targets`` defaults to the testcases dir. Raises ValueError on a pytest
    collection error (propagated from collect_pytest_nodeids)."""
    collect_targets = targets or [_TESTCASES_DIR]
    args = _build_list_selection_args(
        match=match,
        marker=marker,
        category=category,
        skip_slow=skip_slow,
        only_slow=only_slow,
        module=module,
        interface=interface,
        slot=slot,
    )
    return sorted(set(collect_pytest_nodeids(collect_targets, args)))


def _emit_nodeids(nodeids: list[str]) -> None:
    """Write node-ids to stdout, one per line, plain (pipeable)."""
    if nodeids:
        print("\n".join(nodeids))


def list_tests_command(
    targets: list[str] = typer.Argument(  # noqa: B008
        None, help="Paths to scope collection (default: all test cases)"
    ),
    match: str | None = typer.Option(None, "--match", help="Node-id name pattern (pytest -k)"),
    marker: str | None = typer.Option(None, "--marker", help="Marker expression (pytest -m)"),
    category: str | None = typer.Option(None, "--category", "-c", help="Category (pytest -k)"),
    skip_slow: bool = typer.Option(False, "--skip-slow", help="Exclude slow tests"),
    only_slow: bool = typer.Option(False, "--only-slow", help="Only slow tests"),
    module: Path | None = typer.Option(
        None, "--module", "-m", help="Optional module: enumerate mechanism-driven variants too"
    ),
    interface: str = typer.Option("auto", "--interface", "-i", help="Interface version"),
    slot: int = typer.Option(0, "--slot", help="Slot index"),
) -> None:
    """Enumerate pytest node-ids matching a selection, one per line to stdout.

    For building disabled-tests files without repeated live runs (issue #6). Node-ids
    are forward-slash on every platform. Diagnostics go to stderr, so
    ``list-tests --match X > disabled.txt`` yields a clean file.
    """
    try:
        nodeids = enumerate_nodeids(
            list(targets or []),
            match=match,
            marker=marker,
            category=category,
            skip_slow=skip_slow,
            only_slow=only_slow,
            module=module,
            interface=interface,
            slot=slot,
        )
    except ValueError as exc:
        _err.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    _emit_nodeids(nodeids)
    selection = match or marker or category or "all"
    _err.print(f"[dim]{len(nodeids)} node-ids matched ({selection})[/dim]")
