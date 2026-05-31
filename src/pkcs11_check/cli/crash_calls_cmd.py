"""`pkcs11-check crash-calls` -- pinpoint the C_* call each crashed unit died in."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from pkcs11_check.core.crash_journal import summarize_crash_journals

console = Console()


def crash_calls_command(
    journal_dir: Path = typer.Argument(
        ...,
        help="Directory of CK_RV crash journals "
        "(PKCS11_CHECK_RV_TRACE_JOURNAL_DIR from an isolated run)",
    ),
) -> None:
    """Show, per crashed unit, the last C_* call before the crash + its journal file.

    Reads the write-ahead journals written when crash journaling is enabled
    (``PKCS11_CHECK_RV_TRACE_JOURNAL_DIR=<dir>``). Each journal that ends on an
    unmatched call is a crash; the trailing call is where the module died.
    """
    rows = summarize_crash_journals(journal_dir)
    if not rows:
        console.print(
            f"[yellow]No crash journals with an incomplete call in[/yellow] {journal_dir}"
        )
        return
    console.print(f"[bold]{len(rows)} crash journal(s) in[/bold] {journal_dir}:")
    for r in rows:
        mech = r.get("mech")
        extras = "".join(f" {k}={r[k]}" for k in ("mech_params", "in_len", "out_len") if k in r)
        console.print(
            f"  [red]{r['fn']}[/red] i={r['i']} mech={mech}{extras}  [dim]{r['journal']}[/dim]"
        )
