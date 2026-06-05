"""pkcs11-check doctor command - diagnose module / slot / PIN / token / data setup.

Turns the three worst first-run cliffs (wrong slot, wrong PIN, uninitialized
token) and the "is my module even loadable / is data fetched" questions into a
checklist with one actionable next step each. Read-only and non-destructive: a
single login attempt (only when a PIN is supplied), never echoing the PIN.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import typer
from rich.console import Console

from pkcs11_check.core.doctor_probe import run_login_probe_subprocess
from pkcs11_check.core.preflight import run_preflight_subprocess

console = Console()

_OK = "[green]✓[/green]"
_BAD = "[red]✗[/red]"
_SKIP = "[dim]–[/dim]"


def _line(mark: str, label: str, detail: str = "") -> None:
    console.print(f"  {mark} {label}" + (f"  [dim]{detail}[/dim]" if detail else ""))


def doctor_command(
    module: Path = typer.Option(..., "--module", "-m", help="Path to PKCS#11 module"),
    interface: str = typer.Option("auto", "--interface", "-i", help="Interface version"),
    slot: int = typer.Option(0, "--slot", help="Slot index (0-based, NOT the provider's slot ID)"),
    pin: str | None = typer.Option(
        None, "--pin", help="PIN to verify login (prefer P11TEST_PIN env). Single attempt."
    ),
    timeout: int = typer.Option(30, "--timeout", "-t", help="Per-probe timeout (seconds)"),
) -> None:
    """Diagnose a PKCS#11 module setup and print the next step for any problem."""
    console.print(f"[bold]pkcs11-check doctor[/bold] — {module}\n")
    ok = True

    # 1. Module file present.
    if not module.exists():
        _line(_BAD, "module file", f"not found: {module}")
        console.print("\n  Next: check the path (and `file <module>` for the arch).")
        raise typer.Exit(code=3)
    _line(_OK, "module file", "exists")

    # 2. Module loads + C_Initialize + slots (crash-safe preflight).
    manifest_fd, manifest_raw = tempfile.mkstemp(prefix="pkcs11-check-doctor-", suffix=".json")
    os.close(manifest_fd)
    manifest_path = Path(manifest_raw)
    try:
        manifest = run_preflight_subprocess(
            module,
            interface=interface,
            slot=slot,
            timeout=max(10, min(timeout, 60)),
            output_path=manifest_path,
        )
    finally:
        manifest_path.unlink(missing_ok=True)

    if manifest.status == "crashed":
        ok = False
        _line(_BAD, "module load / probe", manifest.error or "crashed")
        console.print(
            "\n  The module crashed while probing — that is itself a finding "
            "(an unstable module). Report it / try a different build."
        )
        raise typer.Exit(code=1)
    if manifest.status == "timeout":
        ok = False
        _line(_BAD, "module load / probe", manifest.error or "timed out")
        raise typer.Exit(code=1)
    if manifest.status != "ok":
        ok = False
        err = manifest.error or "unknown error"
        _line(_BAD, "module load / slots", err)
        if "not found" in err and "slot" in err:
            _line(
                _SKIP,
                "hint",
                "--slot is a 0-based INDEX into token-present slots, not the provider's slot ID. "
                "Run `pkcs11-check info` to list them.",
            )
        elif "OSError" in err or "too short" in err or "cannot open" in err.lower():
            _line(_SKIP, "hint", "Not a loadable PKCS#11 library (wrong path or arch).")
        else:
            _line(
                _SKIP,
                "hint",
                "C_Initialize failed — often a config/env issue "
                "(SOFTHSM2_CONF, NSS configDir, KRYOPTIC_CONF).",
            )
        raise typer.Exit(code=1)

    _line(_OK, "module loads + C_Initialize", f"interface v{manifest.interface_version}")
    _line(_OK, "slot index", f"{slot} valid ({manifest.slot_count} token-present slot(s))")
    _line(_OK, "mechanisms advertised", f"{len(manifest.mechanisms)}")

    # 3. Vector data fetched (informational).
    from pkcs11_check.testcases.data import ACVP_DIR, WYCHEPROOF_DIR

    if WYCHEPROOF_DIR.exists() and ACVP_DIR.exists():
        _line(_OK, "vector data", "fetched (Wycheproof + ACVP present)")
    else:
        _line(
            _SKIP,
            "vector data",
            "not fetched — KAT/Wycheproof/ACVP suites will be skipped. "
            "Run `pkcs11-check fetch-data all` for full coverage (optional).",
        )

    # 4. Token / PIN (only when a PIN is available; single, lockout-aware attempt).
    pin_value = pin if pin is not None else os.environ.get("P11TEST_PIN")
    if pin_value is None:
        _line(_SKIP, "token / PIN", "not checked — pass --pin (or set P11TEST_PIN) to verify login")
    else:
        probe = run_login_probe_subprocess(
            module,
            interface=interface,
            slot=slot,
            pin=pin_value.encode("utf-8", "surrogateescape"),
            timeout=max(10, min(timeout, 60)),
        )
        if probe.status == "ok":
            _line(_OK, "token + PIN", "C_Login succeeded")
        elif probe.status == "pin_incorrect":
            ok = False
            _line(_BAD, "PIN", f"incorrect for slot {slot}")
        elif probe.status == "pin_locked":
            ok = False
            _line(
                _BAD, "PIN", "locked (too many wrong attempts) — re-initialize or unlock the token"
            )
        elif probe.status == "token_not_recognized":
            ok = False
            _line(
                _BAD,
                "token",
                "not recognized / not initialized — initialize it "
                "(softhsm2-util --init-token / certutil -N / pkcs11-tool --init-token)",
            )
        elif probe.status in {"crashed", "timeout"}:
            ok = False
            _line(_BAD, "token + PIN", probe.detail or probe.status)
        else:
            ok = False
            _line(_BAD, "token + PIN", probe.detail or "login probe error")

    console.print()
    if ok:
        console.print("[green]All checks passed.[/green] You can run `pkcs11-check test ...`.")
    else:
        console.print("[red]Some checks failed[/red] — fix the items marked above, then re-run.")
        raise typer.Exit(code=1)
