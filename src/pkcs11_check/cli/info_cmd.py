"""pkcs11-check info command - show module information."""

from __future__ import annotations

import dataclasses
import multiprocessing
import queue
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from pkcs11_check.cli._choices import InterfaceChoice
from pkcs11_check.core.loader import load_module


def _mech_sort_key(m: object) -> str:
    """Sort key for mechanisms - handles both Mechanism enum and raw int."""
    name = getattr(m, "name", None)
    if isinstance(name, str):
        return name
    return f"0x{int(m):08x}" if isinstance(m, int) else str(m)


console = Console()


class InfoQueryError(Exception):
    """The isolated module query failed (child error, timeout, or crash)."""


class InfoQueryCrashError(InfoQueryError):
    """The isolated query child died (native crash) instead of answering."""

    def __init__(self, exitcode: int | None) -> None:
        self.exitcode = exitcode
        super().__init__(f"module query child crashed (exit code {exitcode})")


@dataclasses.dataclass(frozen=True)
class SlotInfo:
    """Plain-data view of one slot with a token (picklable across spawn)."""

    index: int
    label: str
    manufacturer_id: str | None
    model: str | None
    mechanisms: tuple[tuple[str, str, str], ...]


@dataclasses.dataclass(frozen=True)
class ModuleInfo:
    """Plain-data view of a module (picklable across spawn)."""

    path: str
    interface_version: str
    interfaces: tuple[str, ...]
    slots: tuple[SlotInfo, ...]


def _collect_module_info(module: str, interface: str) -> ModuleInfo:
    """Query a module and return plain data. Runs in the isolated child."""
    p11 = load_module(Path(module), interface=interface)
    ifaces = p11.get_interface_list()
    iface_strs = tuple(f"{n} v{maj}.{min}" for n, maj, min in ifaces)
    slots: list[SlotInfo] = []
    for i, slot in enumerate(p11.get_slots(token_present=True)):
        token = slot.get_token()
        mechs: list[tuple[str, str, str]] = []
        for mech in sorted(slot.get_mechanisms(), key=_mech_sort_key):
            info = slot.get_mechanism_info(mech)
            mechs.append(
                (
                    _mech_sort_key(mech),
                    str(info.min_key_length) if info else "",
                    str(info.max_key_length) if info else "",
                )
            )
        slots.append(
            SlotInfo(
                index=i,
                label=str(token.label),
                manufacturer_id=getattr(token, "manufacturer_id", None),
                model=getattr(token, "model", None),
                mechanisms=tuple(mechs),
            )
        )
    return ModuleInfo(
        path=str(p11.path),
        interface_version=str(p11.interface_version),
        interfaces=iface_strs,
        slots=tuple(slots),
    )


def _isolated_entry(fn: Callable[..., Any], args: tuple[Any, ...], out: Any) -> None:
    """Spawn-child entry: run ``fn`` and report (ok, payload) back."""
    try:
        out.put((True, fn(*args)))
    except BaseException as exc:  # Child must answer, never hang the parent.
        out.put((False, f"{type(exc).__name__}: {exc}"))


def _run_isolated(fn: Callable[..., Any], *args: Any, timeout: float = 120.0) -> Any:
    """Run ``fn`` in a spawned child; survive its crash, error, or hang.

    F-019: native module code must not be able to take down the parent.
    ``fn`` must be a top-level (picklable) callable; its return value must
    be picklable. Raises :class:`InfoQueryCrashError` when the child dies
    without answering, :class:`InfoQueryError` on child errors/timeouts.
    """
    ctx = multiprocessing.get_context("spawn")
    out: Any = ctx.Queue()
    proc = ctx.Process(target=_isolated_entry, args=(fn, args, out), daemon=True)
    proc.start()
    # Drain-before-join: the parent must read the answer while the child is
    # alive. Joining first deadlocks payloads larger than the pipe buffer --
    # the child cannot finish handing over the answer, so it never exits and
    # the join burns the whole timeout. Poll in short slices so a fast child
    # death still surfaces promptly instead of waiting out the timeout.
    deadline = time.monotonic() + timeout
    answer: Any = None
    while time.monotonic() < deadline:
        try:
            answer = out.get(timeout=min(0.5, max(deadline - time.monotonic(), 0)))
        except queue.Empty:
            if not proc.is_alive():
                break
            continue
        break
    if answer is None:
        if proc.is_alive():
            proc.terminate()
            proc.join(10)
            raise InfoQueryError(f"module query timed out after {timeout:g}s")
        proc.join(10)
        raise InfoQueryCrashError(proc.exitcode)
    ok, payload = answer
    proc.join(10)
    if proc.is_alive():
        proc.terminate()
        proc.join(10)
    if proc.exitcode != 0:
        raise InfoQueryCrashError(proc.exitcode)
    if not ok:
        raise InfoQueryError(str(payload))
    return payload


def _render_module_info(info: ModuleInfo) -> None:
    """Render collected module data as rich tables (parent side)."""
    console.print(f"[bold]Module:[/bold] {info.path}")
    console.print(f"[bold]Interface:[/bold] v{info.interface_version}")

    if info.interfaces:
        console.print(f"[bold]Available interfaces:[/bold] {', '.join(info.interfaces)}")

    console.print(f"\n[bold]Slots with tokens:[/bold] {len(info.slots)}")

    for slot in info.slots:
        console.print(f"\n  [bold]Slot {slot.index}:[/bold] {slot.label}")
        if slot.manufacturer_id is not None:
            console.print(f"    Manufacturer: {slot.manufacturer_id}")
        if slot.model is not None:
            console.print(f"    Model: {slot.model}")

        table = Table(title=f"Mechanisms ({len(slot.mechanisms)})")
        table.add_column("Mechanism", style="cyan")
        table.add_column("Min Key", justify="right")
        table.add_column("Max Key", justify="right")
        for name, min_key, max_key in slot.mechanisms:
            table.add_row(name, min_key, max_key)
        console.print(table)


def info_command(
    module: Path = typer.Option(..., "--module", "-m", help="Path to PKCS#11 module"),
    interface: InterfaceChoice = typer.Option(
        "auto", "--interface", "-i", help="Interface version"
    ),
) -> None:
    """Show PKCS#11 module information: version, slots, mechanisms."""
    if not module.exists():
        console.print(f"[red]Error:[/red] Module not found: {module}")
        raise typer.Exit(code=3)

    try:
        info = _run_isolated(_collect_module_info, str(module), interface)
    except InfoQueryCrashError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=3) from exc
    except InfoQueryError as exc:
        console.print(f"[red]Error loading module:[/red] {exc}")
        raise typer.Exit(code=3) from exc

    _render_module_info(info)
