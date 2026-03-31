"""pkcs11-check test command - run PKCS#11 test suite."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Literal, cast

import pytest
import typer
from rich.console import Console

from pkcs11_check.config import P11TestConfig
from pkcs11_check.core.collection import collect_pytest_item_metadata
from pkcs11_check.core.file_runner import (
    IsolatedReportConfig,
    discover_auto_isolation_units,
    discover_pytest_units,
    extract_coverage_from_jsonl,
    extract_quality_report_records_from_jsonl,
    load_run_state,
    postprocess_jsonl_to_unified,
    run_isolated_pytest_units,
    write_quality_json_report,
)
from pkcs11_check.core.preflight import run_preflight_subprocess
from pkcs11_check.core.test_selection import (
    DisabledSelectionPlan,
    build_disabled_selection_plan,
    load_disabled_baseline,
    write_deselect_file,
)

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
    marker: str | None,
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

    if marker:
        args.extend(["-m", marker])

    if match:
        args.extend(["-k", match])
    elif category:
        args.extend(["-k", category])

    if verbose:
        args.append("-v")
    else:
        args.append("-q")

    if include_machine_report_args and output == "junit":
        args.extend(["--junit-xml", output_file or "pkcs11-check-results.xml"])

    args.append("--tb=short")
    args.append("--no-header")
    return args


def _isolated_report_config(output: str, output_file: str | None) -> IsolatedReportConfig | None:
    if output not in {"json", "junit"}:
        return None
    if output == "json":
        results_path = Path(output_file or "pkcs11-check-results.json")
        jsonl_path = results_path.parent / "report.jsonl"
        return IsolatedReportConfig("json", results_path, jsonl_path=jsonl_path)
    return IsolatedReportConfig("junit", Path(output_file or "pkcs11-check-results.xml"))


def test_command(
    module: Path = typer.Option(..., "--module", "-m", help="Path to PKCS#11 module"),
    interface: str = typer.Option("auto", "--interface", "-i", help="Interface version"),
    sessions: int = typer.Option(1, "--sessions", "-s", help="Concurrent sessions"),
    timeout: int = typer.Option(120, "--timeout", "-t", help="Per-test timeout (seconds)"),
    category: str | None = typer.Option(None, "--category", "-c", help="Test categories"),
    match: str | None = typer.Option(None, "--match", help="Test name pattern"),
    marker: str | None = typer.Option(None, "--marker", help="Pytest marker expression (-m)"),
    pin: str | None = typer.Option(None, "--pin", help="PIN (prefer P11TEST_PIN env)"),
    slot: int = typer.Option(0, "--slot", help="Slot index"),
    destructive: bool = typer.Option(False, "--destructive", help="Enable destructive tests"),
    output: str = typer.Option("rich", "--output", "-o", help="Output: rich, json, junit"),
    output_file: str | None = typer.Option(None, "--output-file", help="Output file path"),
    verbose: bool = typer.Option(False, "--verbose", "-V", help="Verbose output"),
    ignore_disabled_tests: bool = typer.Option(
        False,
        "--ignore-disabled-tests",
        help="Do not load the configured disabled baseline for this run",
    ),
    isolation: str = typer.Option(
        "auto",
        "--isolation",
        help="Isolation mode: auto, file, test, none (auto is default; none is fastest but unsafe)",
    ),
    resume: bool = typer.Option(False, "--resume", help="Resume an isolated run"),
    stop_on_failure: bool = typer.Option(
        False,
        "--stop-on-failure",
        help="Stop isolated mode at the first failing/crashing unit",
    ),
    state_file: Path = typer.Option(
        Path(".pkcs11-check-isolation-state.json"),
        "--state-file",
        help="State file for isolated runs",
    ),
    policy_file: Path = typer.Option(
        Path(".pkcs11-check-isolation-policy.json"),
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

    original_pin = os.environ.get("P11TEST_PIN")
    had_original_pin = "P11TEST_PIN" in os.environ

    # Pass PIN via env so pytest fixtures pick it up
    if pin:
        os.environ["P11TEST_PIN"] = pin

    manifest_fd, manifest_raw_path = tempfile.mkstemp(
        prefix="pkcs11-check-manifest-",
        suffix=".json",
    )
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
        marker=marker,
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
        try:
            runtime_config = P11TestConfig(
                module=module,
                interface=interface,
                slot=slot,
                destructive=destructive,
                pin=pin,
            )
            baseline = None
            if not ignore_disabled_tests:
                baseline = load_disabled_baseline(runtime_config.disabled_tests_file)
            disabled_nodeids = set(baseline.disabled_nodeids) if baseline is not None else set()
            baseline_fingerprint = (
                baseline.fingerprint if baseline is not None else "disabled-baseline:none"
            )
        except FileNotFoundError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=2) from exc

        if isolation in {"auto", "file", "test"}:
            if sessions != 1:
                console.print(
                    "[yellow]Warning:[/yellow] "
                    f"--sessions is ignored in --isolation {isolation} mode"
                )

            try:
                collected_items = None
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
                if disabled_nodeids:
                    if isolation == "auto":
                        collected_items = collect_pytest_item_metadata(target_args, pytest_args)
                    elif runner_granularity == "file":
                        collected_items = collect_pytest_item_metadata(target_args, pytest_args)
                    selection_plan = build_disabled_selection_plan(
                        units=units,
                        disabled_nodeids=disabled_nodeids,
                        baseline_fingerprint=baseline_fingerprint,
                        collected_items=collected_items,
                    )
                else:
                    selection_plan = DisabledSelectionPlan(
                        units=units,
                        deselect_by_file={},
                        baseline_fingerprint=baseline_fingerprint,
                    )
                exit_code = run_isolated_pytest_units(
                    selection_plan.units,
                    pytest_args,
                    deselect_by_file=selection_plan.deselect_by_file,
                    baseline_fingerprint=selection_plan.baseline_fingerprint,
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
        # For JSON output, set PKCS11_CHECK_REPORT_LOG so plugin.py injects
        # --report-log into the pytest session for per-test JSONL capture.
        jsonl_raw: str | None = None
        deselect_path: Path | None = None
        if output == "json":
            jsonl_fd, jsonl_raw = tempfile.mkstemp(prefix="pkcs11-check-jsonl-", suffix=".jsonl")
            os.close(jsonl_fd)
            os.environ["PKCS11_CHECK_REPORT_LOG"] = jsonl_raw
        if baseline is not None and baseline.disabled_nodeids:
            deselect_path = write_deselect_file(baseline.disabled_nodeids)
            os.environ["PKCS11_CHECK_DESELECT_FILE"] = str(deselect_path)
        try:
            exit_code = pytest.main(args)
        finally:
            if jsonl_raw is not None:
                os.environ.pop("PKCS11_CHECK_REPORT_LOG", None)
            os.environ.pop("PKCS11_CHECK_DESELECT_FILE", None)
            if deselect_path is not None:
                deselect_path.unlink(missing_ok=True)
        if output == "json" and jsonl_raw is not None:
            jsonl_p = Path(jsonl_raw)
            unified_path = Path(output_file or "pkcs11-check-results.json")
            unified_path.parent.mkdir(parents=True, exist_ok=True)
            coverage_data = extract_coverage_from_jsonl(jsonl_p)
            quality_records = extract_quality_report_records_from_jsonl(jsonl_p)
            if coverage_data:
                coverage_path = unified_path.parent / "coverage.json"
                coverage_path.write_text(json.dumps(coverage_data, indent=2) + "\n")
            results_payload = postprocess_jsonl_to_unified(jsonl_p, unified_path)
            quality_path = unified_path.parent / "quality.json"
            write_quality_json_report(
                quality_path,
                results_payload or {},
                coverage=coverage_data,
                report_log_records=quality_records,
            )
            jsonl_p.unlink(missing_ok=True)
        raise typer.Exit(code=int(exit_code))
    finally:
        manifest_path.unlink(missing_ok=True)
        if pin:
            if had_original_pin:
                os.environ["P11TEST_PIN"] = original_pin or ""
            else:
                os.environ.pop("P11TEST_PIN", None)
