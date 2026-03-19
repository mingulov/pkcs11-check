"""p11test test command — run PKCS#11 test suite."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Literal, cast

import pytest
import typer
from rich.console import Console

from p11test.core.file_runner import (
    IsolatedReportConfig,
    discover_auto_isolation_units,
    discover_pytest_units,
    load_run_state,
    run_isolated_pytest_units,
)
from p11test.core.preflight import run_preflight_subprocess

console = Console(stderr=True)

_TESTCASES_DIR = str(Path(__file__).parent.parent / "testcases")


def _preflight_timeout_seconds(test_timeout: int) -> int:
    return max(10, min(test_timeout, 60))


def _build_pytest_args(
    *,
    module: Path,
    interface: str,
    timeout: int,
    category: str | None,
    match: str | None,
    include_pin_arg: bool,
    pin: str | None,
    slot: int,
    destructive: bool,
    output: str,
    output_file: str | None,
    include_machine_report_args: bool,
    verbose: bool,
) -> list[str]:
    args: list[str] = []
    args.extend(["--p11-module", str(module)])
    args.extend(["--p11-interface", interface])
    args.extend(["--p11-slot", str(slot)])
    args.extend(["--timeout", str(timeout)])

    if include_pin_arg and pin:
        args.extend(["--p11-pin", pin])

    if destructive:
        args.append("--p11-destructive")

    if match:
        args.extend(["-k", match])
    elif category:
        args.extend(["-k", category])

    if verbose:
        args.append("-v")
    else:
        args.append("-q")

    if include_machine_report_args and output == "junit":
        args.extend(["--junit-xml", output_file or "p11test-results.xml"])
    elif include_machine_report_args and output == "json":
        json_file = output_file or "p11test-results.json"
        args.extend(
            [
                "--json-report",
                f"--json-report-file={json_file}",
                "--json-report-omit=collectors",
            ]
        )

    args.append("--tb=short")
    args.append("--no-header")
    return args


def _isolated_report_config(output: str, output_file: str | None) -> IsolatedReportConfig | None:
    if output not in {"json", "junit"}:
        return None
    if output == "json":
        return IsolatedReportConfig("json", Path(output_file or "p11test-results.json"))
    return IsolatedReportConfig("junit", Path(output_file or "p11test-results.xml"))


def test_command(
    module: Path = typer.Option(..., "--module", "-m", help="Path to PKCS#11 module"),
    interface: str = typer.Option("auto", "--interface", "-i", help="Interface version"),
    sessions: int = typer.Option(1, "--sessions", "-s", help="Concurrent sessions"),
    timeout: int = typer.Option(120, "--timeout", "-t", help="Per-test timeout (seconds)"),
    category: str | None = typer.Option(None, "--category", "-c", help="Test categories"),
    match: str | None = typer.Option(None, "--match", help="Test name pattern"),
    pin: str | None = typer.Option(None, "--pin", help="PIN (prefer P11TEST_PIN env)"),
    slot: int = typer.Option(0, "--slot", help="Slot index"),
    destructive: bool = typer.Option(False, "--destructive", help="Enable destructive tests"),
    output: str = typer.Option("rich", "--output", "-o", help="Output: rich, json, junit"),
    output_file: str | None = typer.Option(None, "--output-file", help="Output file path"),
    verbose: bool = typer.Option(False, "--verbose", "-V", help="Verbose output"),
    isolation: str = typer.Option(
        "none", "--isolation", help="Isolation mode: none, auto, file, test"
    ),
    resume: bool = typer.Option(False, "--resume", help="Resume an isolated run"),
    stop_on_failure: bool = typer.Option(
        False,
        "--stop-on-failure",
        help="Stop isolated mode at the first failing/crashing unit",
    ),
    state_file: Path = typer.Option(
        Path(".p11test-isolation-state.json"),
        "--state-file",
        help="State file for isolated runs",
    ),
    policy_file: Path = typer.Option(
        Path(".p11test-isolation-policy.json"),
        "--policy-file",
        help="Adaptive isolation policy file for isolated runs",
    ),
    max_crashes_per_file: int = typer.Option(
        3,
        "--max-crashes-per-file",
        min=0,
        help="In test/auto isolation, skip remaining tests from a file after this many crashes "
        "(0 = unlimited)",
    ),
    targets: list[str] = typer.Argument(None, help="Optional pytest paths or nodeids"),
) -> None:
    """Run the PKCS#11 test suite against a module."""
    if not module.exists():
        console.print(f"[red]Error:[/red] Module not found: {module}")
        raise typer.Exit(code=3)

    if isolation not in {"none", "auto", "file", "test"}:
        console.print(f"[red]Error:[/red] Unsupported isolation mode: {isolation}")
        raise typer.Exit(code=2)

    # Pass PIN via env so pytest fixtures pick it up
    if pin:
        os.environ["P11TEST_PIN"] = pin

    manifest_fd, manifest_raw_path = tempfile.mkstemp(prefix="p11test-manifest-", suffix=".json")
    os.close(manifest_fd)
    manifest_path = Path(manifest_raw_path)

    manifest = run_preflight_subprocess(
        module,
        interface=interface,
        slot=slot,
        timeout=_preflight_timeout_seconds(timeout),
        output_path=manifest_path,
    )
    if manifest.status != "ok":
        console.print(f"[red]Error:[/red] PKCS#11 preflight {manifest.status}: {manifest.error}")
        manifest_path.unlink(missing_ok=True)
        raise typer.Exit(code=1 if manifest.status in {"crashed", "timeout"} else 2)

    pytest_args = _build_pytest_args(
        module=module,
        interface=interface,
        timeout=timeout,
        category=category,
        match=match,
        include_pin_arg=isolation == "none",
        pin=pin,
        slot=slot,
        destructive=destructive,
        output=output,
        output_file=output_file,
        include_machine_report_args=isolation == "none",
        verbose=verbose,
    )
    pytest_args.extend(["--p11-manifest", str(manifest_path)])
    report_config = _isolated_report_config(output, output_file) if isolation != "none" else None

    target_args = targets or [_TESTCASES_DIR]
    try:
        if isolation in {"auto", "file", "test"}:
            if sessions != 1:
                console.print(
                    "[yellow]Warning:[/yellow] "
                    f"--sessions is ignored in --isolation {isolation} mode"
                )

            try:
                if isolation == "auto":
                    prior_state = load_run_state(state_file) if resume else None
                    if prior_state is not None:
                        units = prior_state.units
                    else:
                        units = discover_auto_isolation_units(
                            target_args,
                            Path(_TESTCASES_DIR),
                            pytest_args=pytest_args,
                            policy_file=policy_file,
                        )
                    runner_granularity: Literal["mixed"] | Literal["file", "test"] = "mixed"
                else:
                    isolated_mode = cast(Literal["file", "test"], isolation)
                    units = discover_pytest_units(
                        target_args,
                        Path(_TESTCASES_DIR),
                        granularity=isolated_mode,
                        pytest_args=pytest_args,
                    )
                    runner_granularity = isolated_mode
                exit_code = run_isolated_pytest_units(
                    units,
                    pytest_args,
                    timeout=timeout,
                    state_file=state_file,
                    policy_file=policy_file,
                    report_config=report_config,
                    resume=resume,
                    stop_on_failure=stop_on_failure,
                    console=console,
                    granularity=runner_granularity,
                    max_crashes_per_file=max_crashes_per_file,
                )
            except (FileNotFoundError, ValueError) as exc:
                console.print(f"[red]Error:[/red] {exc}")
                raise typer.Exit(code=2) from exc
            raise typer.Exit(code=exit_code)

        args = [*target_args, *pytest_args]
        exit_code = pytest.main(args)
        raise typer.Exit(code=int(exit_code))
    finally:
        manifest_path.unlink(missing_ok=True)
