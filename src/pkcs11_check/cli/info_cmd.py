"""pkcs11-check info command — show module information."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from pkcs11_check.core.loader import load_module


def _mech_sort_key(m: object) -> str:
    """Sort key for mechanisms — handles both Mechanism enum and raw int."""
    name = getattr(m, "name", None)
    if isinstance(name, str):
        return name
    return f"0x{int(m):08x}" if isinstance(m, int) else str(m)

console = Console()


def info_command(
    module: Path = typer.Option(..., "--module", "-m", help="Path to PKCS#11 module"),
    interface: str = typer.Option("auto", "--interface", "-i", help="Interface version"),
) -> None:
    """Show PKCS#11 module information: version, slots, mechanisms."""
    if not module.exists():
        console.print(f"[red]Error:[/red] Module not found: {module}")
        raise typer.Exit(code=3)

    try:
        p11 = load_module(module, interface=interface)
    except Exception as exc:
        console.print(f"[red]Error loading module:[/red] {exc}")
        raise typer.Exit(code=3) from exc

    console.print(f"[bold]Module:[/bold] {p11.path}")
    console.print(f"[bold]Interface:[/bold] v{p11.interface_version}")

    lib = p11.lib
    if hasattr(lib, "get_interface_list"):
        ifaces = lib.get_interface_list()
        if ifaces:
            iface_strs = ", ".join(f"{n} v{maj}.{min}" for n, maj, min in ifaces)
            console.print(f"[bold]Available interfaces:[/bold] {iface_strs}")
    if hasattr(lib, "manufacturer_id"):
        console.print(f"[bold]Manufacturer:[/bold] {lib.manufacturer_id}")
    if hasattr(lib, "library_description"):
        console.print(f"[bold]Description:[/bold] {lib.library_description}")

    slots = p11.get_slots(token_present=True)
    console.print(f"\n[bold]Slots with tokens:[/bold] {len(slots)}")

    for i, slot in enumerate(slots):
        token = slot.get_token()
        console.print(f"\n  [bold]Slot {i}:[/bold] {token.label}")
        if hasattr(token, "manufacturer_id"):
            console.print(f"    Manufacturer: {token.manufacturer_id}")
        if hasattr(token, "model"):
            console.print(f"    Model: {token.model}")

        mechanisms = slot.get_mechanisms()
        table = Table(title=f"Mechanisms ({len(mechanisms)})")
        table.add_column("Mechanism", style="cyan")
        table.add_column("Min Key", justify="right")
        table.add_column("Max Key", justify="right")
        for mech in sorted(mechanisms, key=_mech_sort_key):
            info = slot.get_mechanism_info(mech)
            min_key = str(info.min_key_length) if info else ""
            max_key = str(info.max_key_length) if info else ""
            table.add_row(_mech_sort_key(mech), min_key, max_key)
        console.print(table)
