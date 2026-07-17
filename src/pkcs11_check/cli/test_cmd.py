"""pkcs11-check test command - run PKCS#11 test suite."""

from __future__ import annotations

import json
import os
import tempfile
import tomllib
from pathlib import Path
from typing import Any, Literal, cast

import pytest
import typer
from pydantic import SecretStr
from rich.console import Console

from pkcs11_check import provenance as provenance_mod
from pkcs11_check.config import P11TestConfig
from pkcs11_check.core.collection import CollectedPytestItem, collect_pytest_item_metadata
from pkcs11_check.core.file_runner import (
    IsolatedReportConfig,
    _emit_external_provision_banner,
    discover_auto_isolation_units,
    discover_pytest_units,
    extract_coverage_from_jsonl,
    extract_provisioning_from_jsonl,
    extract_quality_report_records_from_jsonl,
    load_run_state,
    postprocess_jsonl_to_unified,
    run_isolated_pytest_units,
    validate_subprocess_per_test_expansion,
    write_quality_json_report,
)
from pkcs11_check.core.preflight import run_preflight_subprocess
from pkcs11_check.core.recovery import build_recovery_config
from pkcs11_check.core.test_selection import (
    DisabledSelectionPlan,
    build_disabled_selection_plan,
    load_disabled_baseline,
    write_deselect_file,
)
from pkcs11_check.testcases.data import SOURCES_TOML, resolve_data_dir

console = Console(stderr=True)

_TESTCASES_DIR = str(Path(__file__).parent.parent / "testcases")


def _preflight_timeout_seconds(test_timeout: int) -> int:
    return max(10, min(test_timeout, 60))


def _build_run_provenance(manifest: Any, data_dir: Path) -> dict[str, Any]:
    """Assemble the provenance block for this run (best-effort; never raises)."""
    try:
        environment: dict[str, Any] | None = None
        if getattr(manifest, "interface_version", None) is not None:
            environment = {
                "interface": manifest.interface_version,
                "slots": manifest.slot_count,
                "mechanisms": len(manifest.mechanisms),
            }
        try:
            with open(SOURCES_TOML, "rb") as fh:
                data_manifest: dict[str, Any] = tomllib.load(fh)
        except (OSError, tomllib.TOMLDecodeError):
            data_manifest = {}
        build_file = Path(
            os.environ.get(
                "PKCS11_CHECK_BUILD_PROVENANCE", "/etc/pkcs11-check/build-provenance.json"
            )
        )
        return provenance_mod.assemble(
            env=os.environ,
            repo_root=Path(__file__).resolve().parents[3],
            build_file=build_file,
            data_manifest=data_manifest,
            data_dir=data_dir,
            environment=environment,
        )
    except Exception as exc:  # noqa: BLE001  # best-effort: provenance must never abort the run
        # Never abort the run, but do not lose the error class either (house rule).
        console.print(
            f"[dim]run provenance unavailable ({exc.__class__.__name__}); "
            "report will show build info absent[/dim]"
        )
        return {}


def _combine_marker(marker: str | None, *, skip_slow: bool, only_slow: bool) -> str | None:
    """Combine an explicit --marker expression with the --skip-slow/--only-slow flags."""
    slow_expr: str | None = None
    if only_slow:
        slow_expr = "slow"
    elif skip_slow:
        slow_expr = "not slow"
    if slow_expr is None:
        return marker
    if marker:
        return f"({marker}) and ({slow_expr})"
    return slow_expr


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
    so_pin: str | None,
    slot: int,
    destructive: bool,
    rv_trace: bool,
    rv_trace_compact: int | None,
    output: str,
    output_file: str | None,
    include_machine_report_args: bool,
    verbose: bool,
    key_inject: str,
    wrap_key_source: str,
    wrap_key_label: str | None,
    wrap_key_handle: int | None,
    wrap_key_value: str | None,
    wrap_mech: str | None,
    wrap_rsa_bits: int,
    wrap_oaep_hash: str,
    allow_external_provision: bool,
    external_provision_cmd: str | None,
) -> list[str]:
    args: list[str] = []
    args.extend(["--p11-module", str(module)])
    args.extend(["--p11-interface", interface])
    args.extend(["--p11-slot", str(slot)])
    args.extend(["--timeout", str(timeout)])

    if include_pin_arg and pin:
        args.extend(["--p11-pin", pin])

    if include_pin_arg and so_pin:
        args.extend(["--p11-so-pin", so_pin])

    if destructive:
        args.append("--p11-destructive")

    # CK_RV trace: a stable option, so it flows via pytest_args to both the
    # in-process pytest.main and each isolated subprocess unit (no env bridge
    # needed). --rv-trace-compact implies tracing. See docs/rv-trace-design.md.
    if rv_trace_compact is not None:
        args.append(f"--p11-rv-trace-compact={rv_trace_compact}")
    elif rv_trace:
        args.append("--p11-rv-trace")

    if key_inject != "off":
        args.extend(["--p11-key-inject", key_inject])
    if wrap_key_source != "bootstrap":
        args.extend(["--p11-wrap-key-source", wrap_key_source])
    if wrap_key_label is not None:
        args.extend(["--p11-wrap-key-label", wrap_key_label])
    if wrap_key_handle is not None:
        args.extend(["--p11-wrap-key-handle", str(wrap_key_handle)])
    if wrap_key_value is not None:
        args.extend(["--p11-wrap-key-value", wrap_key_value])
    if wrap_mech is not None:
        args.extend(["--p11-wrap-mech", wrap_mech])
    if wrap_rsa_bits != 2048:
        args.extend(["--p11-wrap-rsa-bits", str(wrap_rsa_bits)])
    if wrap_oaep_hash != "auto":
        args.extend(["--p11-wrap-oaep-hash", wrap_oaep_hash])
    if allow_external_provision:
        args.append("--p11-allow-external-provision")
    if external_provision_cmd is not None:
        args.extend(["--p11-external-provision-cmd", external_provision_cmd])

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
    # pkcs11-check tracks its own run state / resume, so pytest's cache is unused.
    # Disabling it also avoids a "could not create cache path /.pytest_cache"
    # warning when pytest's rootdir resolves to '/' (installed package, no config
    # file above it — see the rootdir handling in core/file_runner.py).
    args.extend(["-p", "no:cacheprovider"])
    return args


def _isolated_report_config(output: str, output_file: str | None) -> IsolatedReportConfig | None:
    if output not in {"json", "junit"}:
        return None
    if output == "json":
        results_path = Path(output_file or "pkcs11-check-results.json")
        jsonl_path = results_path.parent / "report.jsonl"
        return IsolatedReportConfig("json", results_path, jsonl_path=jsonl_path)
    return IsolatedReportConfig("junit", Path(output_file or "pkcs11-check-results.xml"))


def _assemble_json_artifacts_from_jsonl(
    jsonl_p: Path, output_file: str | None, run_provenance: dict[str, Any]
) -> None:
    """Build the results/coverage/quality/provisioning JSON artifacts from a raw report JSONL.

    Used by the non-isolated (``--isolation none``) path; the isolated path produces the same
    artifacts inside ``run_isolated_pytest_units``. Consumes (deletes) the raw JSONL when done.
    """
    unified_path = Path(output_file or "pkcs11-check-results.json")
    unified_path.parent.mkdir(parents=True, exist_ok=True)
    coverage_data = extract_coverage_from_jsonl(jsonl_p)
    quality_records = extract_quality_report_records_from_jsonl(jsonl_p)
    if coverage_data:
        (unified_path.parent / "coverage.json").write_text(
            json.dumps(coverage_data, indent=2) + "\n", encoding="utf-8"
        )
    provisioning_data = extract_provisioning_from_jsonl(jsonl_p)
    if provisioning_data is not None:
        (unified_path.parent / "provisioning.json").write_text(
            json.dumps(provisioning_data, indent=2) + "\n", encoding="utf-8"
        )
        if provisioning_data["totals"].get("ran_via_external", 0) > 0:
            _emit_external_provision_banner(provisioning_data["totals"]["ran_via_external"])
    results_payload = postprocess_jsonl_to_unified(jsonl_p, unified_path, provenance=run_provenance)
    write_quality_json_report(
        unified_path.parent / "quality.json",
        results_payload,
        coverage=coverage_data,
        report_log_records=quality_records,
    )
    jsonl_p.unlink(missing_ok=True)


def test_command(
    module: Path = typer.Option(..., "--module", "-m", help="Path to PKCS#11 module"),
    interface: str = typer.Option("auto", "--interface", "-i", help="Interface version"),
    sessions: int = typer.Option(
        1, "--sessions", "-s", help="Concurrent sessions", rich_help_panel="Advanced"
    ),
    timeout: int = typer.Option(180, "--timeout", "-t", help="Per-test timeout (seconds)"),
    category: str | None = typer.Option(None, "--category", "-c", help="Test categories"),
    match: str | None = typer.Option(None, "--match", help="Test name pattern"),
    marker: str | None = typer.Option(None, "--marker", help="Pytest marker expression (-m)"),
    skip_slow: bool = typer.Option(
        False, "--skip-slow", help="Fast profile: skip long-running tests (-m 'not slow')"
    ),
    only_slow: bool = typer.Option(
        False, "--only-slow", help="Run only the long-running tests (-m 'slow')"
    ),
    pin: str | None = typer.Option(None, "--pin", help="PIN (prefer P11TEST_PIN env)"),
    so_pin: str | None = typer.Option(
        None, "--so-pin", help="SO PIN for CKU_SO tests (prefer P11TEST_SO_PIN env)"
    ),
    slot: int = typer.Option(0, "--slot", help="Slot index"),
    destructive: bool = typer.Option(
        False, "--destructive", help="Enable destructive tests", rich_help_panel="Advanced"
    ),
    output: str = typer.Option("rich", "--output", "-o", help="Output: rich, json, junit"),
    output_file: str | None = typer.Option(None, "--output-file", help="Output file path"),
    verbose: bool = typer.Option(False, "--verbose", "-V", help="Verbose output"),
    ignore_disabled_tests: bool = typer.Option(
        False,
        "--ignore-disabled-tests",
        help="Do not load the configured disabled baseline for this run",
        rich_help_panel="Advanced",
    ),
    isolation: str = typer.Option(
        "auto",
        "--isolation",
        help="Isolation mode: auto, file, test, none (auto is default; none is fastest but unsafe)",
        rich_help_panel="Isolation",
    ),
    no_collection_cache: bool = typer.Option(
        False,
        "--no-collection-cache",
        help="Disable the cached collection metadata (always re-collect from scratch)",
        rich_help_panel="Advanced",
    ),
    resume: bool = typer.Option(
        False, "--resume", help="Resume an isolated run", rich_help_panel="Isolation"
    ),
    stop_on_failure: bool = typer.Option(
        False,
        "--stop-on-failure",
        help="Stop isolated mode at the first failing/crashing unit",
        rich_help_panel="Isolation",
    ),
    state_file: Path = typer.Option(
        Path(".pkcs11-check-isolation-state.json"),
        "--state-file",
        help="State file for isolated runs",
        rich_help_panel="Isolation",
    ),
    policy_file: Path = typer.Option(
        Path(".pkcs11-check-isolation-policy.json"),
        "--policy-file",
        help="Adaptive isolation policy file for isolated runs",
        rich_help_panel="Isolation",
    ),
    max_crashes_per_file: int = typer.Option(
        10,
        "--max-crashes-per-file",
        min=0,
        help="In test/auto isolation, skip remaining tests from a file after this many crashes "
        "(0 = unlimited; default 10). Abandoned tests are reported as crash_limited.",
        rich_help_panel="Isolation",
    ),
    rv_trace: bool = typer.Option(
        False,
        "--rv-trace",
        help="Record each C_* call's raw CK_RV per test into report.jsonl user_properties",
        rich_help_panel="CK_RV tracing",
    ),
    rv_trace_compact: int | None = typer.Option(
        None,
        "--rv-trace-compact",
        metavar="N",
        help="Keep only the last N CK_RV trace entries per test (implies --rv-trace)",
        rich_help_panel="CK_RV tracing",
    ),
    key_inject: str = typer.Option(
        "off",
        "--key-inject",
        help="Key-provisioning injection mode: off, unwrap, force-unwrap",
        rich_help_panel="Key provisioning",
    ),
    wrap_key_source: str = typer.Option(
        "bootstrap",
        "--wrap-key-source",
        help="Wrapping KEK source: bootstrap (auto-generate) or configured",
        rich_help_panel="Key provisioning",
    ),
    wrap_key_label: str | None = typer.Option(
        None,
        "--wrap-key-label",
        help="Label of the configured wrapping key",
        rich_help_panel="Key provisioning",
    ),
    wrap_key_handle: int | None = typer.Option(
        None,
        "--wrap-key-handle",
        help="Handle of the configured wrapping key",
        rich_help_panel="Key provisioning",
    ),
    wrap_key_value: str | None = typer.Option(
        None,
        "--wrap-key-value",
        help="Hex value of a symmetric configured KEK",
        rich_help_panel="Key provisioning",
    ),
    wrap_mech: str | None = typer.Option(
        None,
        "--wrap-mech",
        help="Override auto-selected unwrap mechanism (e.g. CKM_RSA_AES_KEY_WRAP)",
        rich_help_panel="Key provisioning",
    ),
    wrap_rsa_bits: int = typer.Option(
        2048,
        "--wrap-rsa-bits",
        help="RSA key size in bits for bootstrap wrapping key",
        rich_help_panel="Key provisioning",
    ),
    wrap_oaep_hash: str = typer.Option(
        "auto",
        "--wrap-oaep-hash",
        help="OAEP hash for wrapping: auto (probe; prefer sha256, fall back sha1), sha1, or sha256",
        rich_help_panel="Key provisioning",
    ),
    recover_mode: str = typer.Option(
        "off",
        "--recover-mode",
        help="Crashing-daemon recovery: off (default), wait (pause for an external supervisor to "
        "restart the daemon), or cmd (run --recover-cmd). Use wait if anything else restarts it.",
        rich_help_panel="Daemon recovery",
    ),
    recover_cmd: str | None = typer.Option(
        None,
        "--recover-cmd",
        envvar="P11TEST_RECOVER_CMD",
        help="No-shell argv (tokenized) run between tests when the provider is detected down; "
        "implies --recover-mode cmd. Only for daemons nothing else restarts.",
        rich_help_panel="Daemon recovery",
    ),
    allow_external_provision: bool = typer.Option(
        False,
        "--allow-external-provision",
        help=(
            "Strict acknowledgement enabling external-tool provisioning "
            "(requires --external-provision-cmd)"
        ),
        rich_help_panel="Key provisioning",
    ),
    external_provision_cmd: str | None = typer.Option(
        None,
        "--external-provision-cmd",
        help=(
            "Operator command template loading a key into the backend; "
            "placeholders {keyfile} {label} {key_type} {key_class}"
        ),
        rich_help_panel="Key provisioning",
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

    if skip_slow and only_slow:
        console.print("[red]Error:[/red] --skip-slow and --only-slow are mutually exclusive")
        raise typer.Exit(code=2)
    marker = _combine_marker(marker, skip_slow=skip_slow, only_slow=only_slow)

    if no_collection_cache:
        os.environ["PKCS11_CHECK_NO_COLLECTION_CACHE"] = "1"

    original_pin = os.environ.get("P11TEST_PIN")
    had_original_pin = "P11TEST_PIN" in os.environ

    # Pass PIN via env so pytest fixtures pick it up
    if pin:
        os.environ["P11TEST_PIN"] = pin

    original_so_pin = os.environ.get("P11TEST_SO_PIN")
    had_original_so_pin = "P11TEST_SO_PIN" in os.environ

    if so_pin:
        os.environ["P11TEST_SO_PIN"] = so_pin

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

    run_provenance = _build_run_provenance(manifest, resolve_data_dir())
    fw = run_provenance.get("framework") or {}
    fw_version = fw.get("version") or "?"
    prov_info = run_provenance.get("provider") or {}
    if prov_info.get("name"):
        commit_short = (prov_info.get("commit") or "")[:8]
        ref = prov_info.get("ref", "")
        prov_line = f"{prov_info['name']} {ref}@{commit_short}".strip()
    else:
        prov_line = ""
    console.print(
        f"[dim]provenance: pkcs11-check {fw_version}"
        f" | {prov_line or 'provider: build info absent'}[/dim]"
    )

    pytest_args = _build_pytest_args(
        module=module,
        interface=interface,
        timeout=timeout,
        category=category,
        match=match,
        marker=marker,
        include_pin_arg=isolation == "none",
        pin=pin,
        so_pin=so_pin,
        slot=slot,
        destructive=destructive,
        rv_trace=rv_trace,
        rv_trace_compact=rv_trace_compact,
        output=output,
        output_file=output_file,
        include_machine_report_args=isolation == "none",
        verbose=verbose,
        key_inject=key_inject,
        wrap_key_source=wrap_key_source,
        wrap_key_label=wrap_key_label,
        wrap_key_handle=wrap_key_handle,
        wrap_key_value=wrap_key_value,
        wrap_mech=wrap_mech,
        wrap_rsa_bits=wrap_rsa_bits,
        wrap_oaep_hash=wrap_oaep_hash,
        allow_external_provision=allow_external_provision,
        external_provision_cmd=external_provision_cmd,
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
                pin=SecretStr(pin) if pin is not None else None,
                key_inject=key_inject,
                wrap_key_source=wrap_key_source,
                wrap_key_label=wrap_key_label,
                wrap_key_handle=wrap_key_handle,
                wrap_key_value=wrap_key_value,
                wrap_mech=wrap_mech,
                wrap_rsa_bits=wrap_rsa_bits,
                wrap_oaep_hash=wrap_oaep_hash,
                allow_external_provision=allow_external_provision,
                external_provision_cmd=external_provision_cmd,
            )
            baseline = None
            if not ignore_disabled_tests:
                disabled_path = runtime_config.disabled_tests_file
                if disabled_path is None:
                    from pkcs11_check.core.test_selection import (
                        auto_discover_disabled_baseline,
                    )

                    disabled_path = auto_discover_disabled_baseline()
                    if disabled_path is not None:
                        console.print(
                            f"[dim]Using auto-discovered disabled baseline: {disabled_path}[/dim]"
                        )
                baseline = load_disabled_baseline(disabled_path)
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
                auto_collected: list[CollectedPytestItem] | None = None
                if isolation == "auto":
                    prior_state = load_run_state(state_file) if resume else None
                    if prior_state is not None:
                        units = prior_state.units
                        validate_subprocess_per_test_expansion(
                            units,
                            collect_pytest_item_metadata(target_args, pytest_args),
                        )
                    else:
                        # Capture the collection metadata produced during unit
                        # discovery so we don't run a second identical
                        # --collect-only pass below for the disabled plan.
                        auto_collected = []
                        units = discover_auto_isolation_units(
                            target_args,
                            Path(_TESTCASES_DIR),
                            pytest_args=pytest_args,
                            policy_file=policy_file,
                            collected_out=auto_collected,
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
                        collected_items = (
                            auto_collected
                            if auto_collected is not None
                            else collect_pytest_item_metadata(target_args, pytest_args)
                        )
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
                try:
                    recovery_config = build_recovery_config(
                        mode=recover_mode, recover_cmd=recover_cmd
                    )
                except ValueError as exc:
                    console.print(f"[red]Error:[/red] {exc}")
                    raise typer.Exit(code=2) from exc
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
                    provenance=run_provenance,
                    recovery_config=recovery_config,
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
            _assemble_json_artifacts_from_jsonl(Path(jsonl_raw), output_file, run_provenance)
        raise typer.Exit(code=int(exit_code))
    finally:
        manifest_path.unlink(missing_ok=True)
        if pin:
            if had_original_pin:
                os.environ["P11TEST_PIN"] = original_pin or ""
            else:
                os.environ.pop("P11TEST_PIN", None)
        if so_pin:
            if had_original_so_pin:
                os.environ["P11TEST_SO_PIN"] = original_so_pin or ""
            else:
                os.environ.pop("P11TEST_SO_PIN", None)
