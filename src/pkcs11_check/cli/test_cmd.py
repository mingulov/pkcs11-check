"""pkcs11-check test command - run PKCS#11 test suite."""

from __future__ import annotations

import json
import os
import tempfile
import tomllib
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any, Literal, cast

import pytest
import typer
from pydantic import SecretStr
from rich.console import Console

from pkcs11_check import provenance as provenance_mod
from pkcs11_check.config import P11TestConfig
from pkcs11_check.core._report_records import (
    _build_detail_from_report_records,
    _build_per_unit_details_from_record_sources,
    _seed_missing_report_record_caches_from_jsonl,
    _write_report_jsonl_from_record_sources,
)
from pkcs11_check.core.collection import CollectedPytestItem, collect_pytest_item_metadata
from pkcs11_check.core.collection_errors import (
    collection_failure_sidecar_path,
    ensure_failed_collection_report,
)
from pkcs11_check.core.disabled_baseline import resolve_disabled_nodeids
from pkcs11_check.core.file_runner import (
    FileRunResult,
    FileRunState,
    IsolatedReportConfig,
    _collection_failure_reporting_copy,
    _emit_external_provision_banner,
    _reset_fresh_run_artifacts,
    _resume_exit_code,
    discover_auto_isolation_units,
    discover_pytest_units,
    extract_coverage_from_jsonl,
    extract_provisioning_from_jsonl,
    extract_quality_report_records_from_jsonl,
    load_run_state,
    postprocess_jsonl_to_unified,
    run_isolated_pytest_units,
    validate_subprocess_per_test_expansion,
    write_isolated_json_report,
    write_isolated_junit_report,
    write_isolated_report,
    write_quality_json_report,
)
from pkcs11_check.core.preflight import run_preflight_subprocess
from pkcs11_check.core.recovery import build_recovery_config
from pkcs11_check.core.report_log import SessionCompletionTracker, iter_report_log_records
from pkcs11_check.core.test_selection import (
    DisabledSelectionPlan,
    build_disabled_selection_plan,
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


def _ensure_nonisolated_completion_record(
    report_path: Path,
    *,
    returncode: int,
    stdout: str,
    stderr: str,
) -> bool:
    """Append one typed harness record when the captured pytest session is incomplete."""
    completion = SessionCompletionTracker()
    first_target: str | None = None
    has_harness_error = False
    for record in iter_report_log_records(report_path, on_invalid=completion.invalidate):
        completion.observe(record)
        report_type = record.get("$report_type")
        if report_type == "HarnessError":
            has_harness_error = True
        elif first_target is None and report_type in {"TestReport", "CollectReport"}:
            nodeid = record.get("nodeid")
            if isinstance(nodeid, str) and nodeid:
                first_target = nodeid.split("::", 1)[0]
    verified = (
        returncode in {0, 1, 5}
        and completion.complete
        and completion.starts == 1
        and completion.finishes == 1
        and completion.single_exitstatus == returncode
    )
    if verified:
        return True

    if not has_harness_error:
        target = first_target or "<harness>"
        diagnostic = (
            stderr.strip()
            or stdout.strip()
            or (
                f"pytest exited with code {returncode} without a complete SessionFinish "
                f"matching the raw exit code"
            )
        )
        with report_path.open("a", encoding="utf-8") as report_fh:
            report_fh.write(
                json.dumps(
                    {
                        "$report_type": "HarnessError",
                        "nodeid": target,
                        "outcome": "error",
                        "returncode": returncode,
                        "completion_verified": False,
                        "longrepr": diagnostic,
                    }
                )
                + "\n"
            )
    return False


def _persist_collection_failure(
    *,
    diagnostic: str,
    state_file: Path,
    report_config: IsolatedReportConfig | None,
    resume: bool,
    provenance: dict[str, Any],
) -> None:
    """Persist collection failure evidence before the isolated runner can start."""
    target = "<collection>"
    if not resume:
        _reset_fresh_run_artifacts(state_file, report_config)
        prior_state = None
    else:
        prior_state = load_run_state(state_file)

    jsonl_path = report_config.jsonl_path if report_config is not None else None
    collection_sidecar = collection_failure_sidecar_path(state_file)
    for path in (collection_sidecar, jsonl_path):
        if path is not None:
            ensure_failed_collection_report(
                path,
                target=target,
                status="failed",
                returncode=2,
                stdout="",
                stderr=diagnostic,
            )

    base_state = prior_state or FileRunState(units=[], fingerprint="", results=[])
    inline_records_by_unit: dict[str, Sequence[Mapping[str, Any]]] = dict(
        base_state.report_records_by_unit
    )
    reporting_state, inline_records_by_unit = _collection_failure_reporting_copy(
        state_file,
        base_state,
        inline_records_by_unit,
    )

    if report_config is None:
        return
    if jsonl_path is not None and jsonl_path.exists():
        candidate_targets = set(reporting_state.units) | {
            result.target for result in reporting_state.results
        }
        _seed_missing_report_record_caches_from_jsonl(
            state_file,
            jsonl_path,
            candidate_targets=candidate_targets,
            skip_units=set(inline_records_by_unit),
        )
        _write_report_jsonl_from_record_sources(
            state_file,
            units=reporting_state.units,
            inline_records_by_unit=inline_records_by_unit,
            output_path=jsonl_path,
            collection_failure_path=collection_sidecar,
        )
    details = _build_per_unit_details_from_record_sources(
        state_file,
        units=reporting_state.units,
        inline_records_by_unit=inline_records_by_unit,
    )
    if report_config.output_format == "json":
        payload = write_isolated_json_report(
            report_config.output_path,
            reporting_state,
            per_unit_details=details,
            provenance=provenance,
        )
        write_quality_json_report(
            report_config.output_path.parent / "quality.json",
            payload,
            report_log_records=(
                extract_quality_report_records_from_jsonl(jsonl_path)
                if jsonl_path is not None
                else []
            ),
        )
    else:
        write_isolated_report(report_config, reporting_state, per_unit_details=details)


def _assemble_json_artifacts_from_jsonl(
    jsonl_p: Path,
    output_file: str | None,
    run_provenance: dict[str, Any],
    *,
    returncode: int = 0,
    completion_verified: bool | None = None,
) -> dict[str, Any]:
    """Build the results/coverage/quality/provisioning JSON artifacts from a raw report JSONL.

    Used by the non-isolated (``--isolation none``) path; the isolated path produces the same
    artifacts inside ``run_isolated_pytest_units``. Moves the raw JSONL to the documented
    ``report.jsonl`` artifact when done.
    """
    unified_path = Path(output_file or "pkcs11-check-results.json")
    unified_path.parent.mkdir(parents=True, exist_ok=True)
    report_path = unified_path.parent / "report.jsonl"
    jsonl_p.replace(report_path)
    if returncode in {2, 3, 4} or (returncode == 1 and completion_verified is not False):
        ensure_failed_collection_report(
            report_path,
            # Non-isolated output contains one session for all selected targets;
            # any native collection report in it is sufficient evidence for the run.
            target=None,
            status="failed",
            returncode=returncode,
            stdout="",
            stderr="",
        )
    coverage_data = extract_coverage_from_jsonl(report_path)
    quality_records = extract_quality_report_records_from_jsonl(report_path)
    if coverage_data:
        (unified_path.parent / "coverage.json").write_text(
            json.dumps(coverage_data, indent=2) + "\n", encoding="utf-8"
        )
    else:
        (unified_path.parent / "coverage.json").unlink(missing_ok=True)
    provisioning_data = extract_provisioning_from_jsonl(report_path)
    if provisioning_data is not None:
        (unified_path.parent / "provisioning.json").write_text(
            json.dumps(provisioning_data, indent=2) + "\n", encoding="utf-8"
        )
        if provisioning_data["totals"].get("ran_via_external", 0) > 0:
            _emit_external_provision_banner(provisioning_data["totals"]["ran_via_external"])
    else:
        (unified_path.parent / "provisioning.json").unlink(missing_ok=True)
    results_payload = postprocess_jsonl_to_unified(
        report_path, unified_path, provenance=run_provenance
    )
    if completion_verified is False or (completion_verified is None and returncode in {2, 3, 4}):
        for unit in results_payload.get("units", []):
            if isinstance(unit, dict):
                unit["returncode"] = returncode
                unit["completion_verified"] = False
                unit["incomplete"] = True
        results_payload["summary"]["incomplete"] = True
        unified_path.write_text(
            json.dumps(results_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    write_quality_json_report(
        unified_path.parent / "quality.json",
        results_payload,
        coverage=coverage_data,
        report_log_records=quality_records,
    )
    return results_payload


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
        False,
        "--resume",
        help="Continue a saved isolated run; skip targets already attempted",
        rich_help_panel="Isolation",
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
        raise typer.Exit(code=_resume_exit_code(state_file, 3) if resume else 3)

    if isolation not in {"none", "auto", "file", "test"}:
        console.print(f"[red]Error:[/red] Unsupported isolation mode: {isolation}")
        raise typer.Exit(code=_resume_exit_code(state_file, 2) if resume else 2)

    if skip_slow and only_slow:
        console.print("[red]Error:[/red] --skip-slow and --only-slow are mutually exclusive")
        raise typer.Exit(code=_resume_exit_code(state_file, 2) if resume else 2)
    marker = _combine_marker(marker, skip_slow=skip_slow, only_slow=only_slow)

    original_pin = os.environ.get("P11TEST_PIN")
    had_original_pin = "P11TEST_PIN" in os.environ
    original_so_pin = os.environ.get("P11TEST_SO_PIN")
    had_original_so_pin = "P11TEST_SO_PIN" in os.environ

    original_no_collection_cache = os.environ.get("PKCS11_CHECK_NO_COLLECTION_CACHE")
    had_no_collection_cache = "PKCS11_CHECK_NO_COLLECTION_CACHE" in os.environ
    original_report_log = os.environ.get("PKCS11_CHECK_REPORT_LOG")
    had_report_log = "PKCS11_CHECK_REPORT_LOG" in os.environ
    original_deselect_file = os.environ.get("PKCS11_CHECK_DESELECT_FILE")
    had_deselect_file = "PKCS11_CHECK_DESELECT_FILE" in os.environ
    manifest_path: Path | None = None
    manifest_fd: int | None = None
    jsonl_path: Path | None = None
    jsonl_fd: int | None = None
    deselect_path: Path | None = None

    def restore_caller_environment() -> None:
        if had_original_pin:
            os.environ["P11TEST_PIN"] = original_pin or ""
        else:
            os.environ.pop("P11TEST_PIN", None)
        if had_original_so_pin:
            os.environ["P11TEST_SO_PIN"] = original_so_pin or ""
        else:
            os.environ.pop("P11TEST_SO_PIN", None)
        if had_no_collection_cache:
            os.environ["PKCS11_CHECK_NO_COLLECTION_CACHE"] = original_no_collection_cache or ""
        else:
            os.environ.pop("PKCS11_CHECK_NO_COLLECTION_CACHE", None)
        if had_report_log:
            os.environ["PKCS11_CHECK_REPORT_LOG"] = original_report_log or ""
        else:
            os.environ.pop("PKCS11_CHECK_REPORT_LOG", None)
        if had_deselect_file:
            os.environ["PKCS11_CHECK_DESELECT_FILE"] = original_deselect_file or ""
        else:
            os.environ.pop("PKCS11_CHECK_DESELECT_FILE", None)

    def close_manifest_fd() -> None:
        nonlocal manifest_fd
        if manifest_fd is None:
            return
        try:
            os.close(manifest_fd)
        except Exception:  # noqa: BLE001  # cleanup must not mask the original error
            try:
                os.close(manifest_fd)
            except Exception:  # noqa: BLE001  # cleanup must not mask the original error
                return
            manifest_fd = None
        else:
            manifest_fd = None

    def close_jsonl_fd() -> None:
        nonlocal jsonl_fd
        if jsonl_fd is None:
            return
        try:
            os.close(jsonl_fd)
        except Exception:  # noqa: BLE001  # cleanup must not mask the original error
            try:
                os.close(jsonl_fd)
            except Exception:  # noqa: BLE001  # cleanup must not mask the original error
                return
            jsonl_fd = None
        else:
            jsonl_fd = None

    def cleanup_owned_resources() -> None:
        # Restore caller-owned environment first; cleanup failures must not hide it.
        restore_caller_environment()
        close_manifest_fd()
        close_jsonl_fd()
        for path in (manifest_path, jsonl_path, deselect_path):
            if path is not None:
                with suppress(Exception):
                    path.unlink(missing_ok=True)

    try:
        manifest_fd, manifest_raw_path = tempfile.mkstemp(
            prefix="pkcs11-check-manifest-",
            suffix=".json",
        )
        manifest_path = Path(manifest_raw_path)
        os.close(manifest_fd)
        manifest_fd = None

        if no_collection_cache:
            os.environ["PKCS11_CHECK_NO_COLLECTION_CACHE"] = "1"

        # Pass PIN via env so pytest fixtures pick it up
        if pin:
            os.environ["P11TEST_PIN"] = pin
        if so_pin:
            os.environ["P11TEST_SO_PIN"] = so_pin

        assert manifest_path is not None
        manifest = run_preflight_subprocess(
            module,
            interface=interface,
            slot=slot,
            timeout=_preflight_timeout_seconds(timeout),
            output_path=manifest_path,
        )
        if manifest.status != "ok":
            console.print(
                f"[red]Error:[/red] PKCS#11 preflight {manifest.status}: {manifest.error}"
            )
            if output == "json" and manifest.status in {"crashed", "timeout"}:
                results_path = Path(output_file or "pkcs11-check-results.json")
                observation = manifest.process_observation
                raw_code = (
                    observation.get("termination", {}).get("raw_code")
                    if isinstance(observation, dict)
                    and isinstance(observation.get("termination"), dict)
                    else None
                )
                legacy_returncode = (
                    124
                    if manifest.status == "timeout"
                    else (int(raw_code) if isinstance(raw_code, int) else 1)
                )
                result = FileRunResult(
                    target=str(module),
                    status=manifest.status,
                    returncode=legacy_returncode,
                    duration_s=0.0,
                )
                state = FileRunState(
                    units=[str(module)],
                    fingerprint="",
                    results=[result],
                    process_observations=[observation] if isinstance(observation, dict) else [],
                )
                payload = write_isolated_json_report(results_path, state)
                payload["summary"]["incomplete"] = True
                results_path.write_text(
                    json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
                )
            if manifest.status in {"crashed", "timeout"}:
                preflight_exit_code = 1
            elif manifest.reason == "module_unloadable":
                preflight_exit_code = 3
            else:
                preflight_exit_code = 2
            if resume:
                preflight_exit_code = _resume_exit_code(state_file, preflight_exit_code)
            raise typer.Exit(code=preflight_exit_code)

        assert manifest_path is not None
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
        report_config = (
            _isolated_report_config(output, output_file) if isolation != "none" else None
        )

        target_args = targets or [_TESTCASES_DIR]
        if isolation in {"auto", "file", "test"} and not resume:
            # Remove stale output/state before any metadata collection can fail. The
            # isolated runner repeats this reset when execution starts; keeping it
            # here closes the pre-run collection gap.
            _reset_fresh_run_artifacts(state_file, report_config)
        try:
            runtime_config = P11TestConfig(
                module=module,
                interface=interface,
                slot=slot,
                destructive=destructive,
                pin=SecretStr(pin) if pin is not None else None,
                key_inject=key_inject,
                wrap_key_source=cast(Literal["bootstrap", "configured"], wrap_key_source),
                wrap_key_label=wrap_key_label,
                wrap_key_handle=wrap_key_handle,
                wrap_key_value=wrap_key_value,
                wrap_mech=wrap_mech,
                wrap_rsa_bits=wrap_rsa_bits,
                wrap_oaep_hash=wrap_oaep_hash,
                allow_external_provision=allow_external_provision,
                external_provision_cmd=external_provision_cmd,
            )
            # Shared with list-tests so the two commands cannot disagree about which
            # node-ids are in play (GH #6).
            disabled_nodeids, baseline_fingerprint = resolve_disabled_nodeids(
                disabled_tests_file=runtime_config.disabled_tests_file,
                ignore=ignore_disabled_tests,
                on_auto_discover=lambda path: console.print(
                    f"[dim]Using auto-discovered disabled baseline: {path}[/dim]"
                ),
            )
        except FileNotFoundError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            setup_exit_code = _resume_exit_code(state_file, 2) if resume else 2
            raise typer.Exit(code=setup_exit_code) from exc

        if isolation in {"auto", "file", "test"}:
            collection_phase = True
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
                        collected_items = collect_pytest_item_metadata(target_args, pytest_args)
                        auto_collected = collected_items
                        collection_phase = False
                        validate_subprocess_per_test_expansion(
                            units,
                            collected_items,
                        )
                        collection_phase = True
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
                        collected_items = auto_collected
                    runner_granularity: Literal["mixed"] | Literal["file", "test"] = "mixed"
                else:
                    isolated_mode = cast(Literal["file", "test"], isolation)
                    explicit_collected: list[CollectedPytestItem] | None = (
                        [] if isolated_mode == "test" and disabled_nodeids else None
                    )
                    if explicit_collected is None:
                        units = discover_pytest_units(
                            target_args,
                            Path(_TESTCASES_DIR),
                            granularity=isolated_mode,
                            pytest_args=pytest_args,
                        )
                    else:
                        units = discover_pytest_units(
                            target_args,
                            Path(_TESTCASES_DIR),
                            granularity=isolated_mode,
                            pytest_args=pytest_args,
                            collected_out=explicit_collected,
                        )
                    if explicit_collected is not None:
                        collected_items = explicit_collected
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
                    collection_phase = False
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
                collection_phase = False
                try:
                    recovery_config = build_recovery_config(
                        mode=recover_mode, recover_cmd=recover_cmd
                    )
                except ValueError as exc:
                    console.print(f"[red]Error:[/red] {exc}")
                    setup_exit_code = _resume_exit_code(state_file, 2) if resume else 2
                    raise typer.Exit(code=setup_exit_code) from exc
                runner_kwargs: dict[str, Any] = {}
                if collected_items:
                    runner_kwargs["collected_items"] = collected_items
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
                    **runner_kwargs,
                )
            except (FileNotFoundError, ValueError) as exc:
                if collection_phase:
                    _persist_collection_failure(
                        diagnostic=str(exc) or type(exc).__name__,
                        state_file=state_file,
                        report_config=report_config,
                        resume=resume,
                        provenance=run_provenance,
                    )
                console.print(f"[red]Error:[/red] {exc}")
                collection_exit_code = 2
                if resume:
                    collection_exit_code = _resume_exit_code(state_file, collection_exit_code)
                raise typer.Exit(code=collection_exit_code) from exc
            raise typer.Exit(code=exit_code)

        args = [*target_args, *pytest_args]
        # Keep report-log evidence for every output mode. JSON moves this temp
        # file to the documented report.jsonl artifact; other modes clean it.
        results_path = Path(output_file or "pkcs11-check-results.json")
        if output == "json":
            results_path.parent.mkdir(parents=True, exist_ok=True)
        jsonl_fd, jsonl_raw = tempfile.mkstemp(
            prefix="pkcs11-check-jsonl-",
            suffix=".jsonl",
            dir=str(results_path.parent) if output == "json" else None,
        )
        jsonl_path = Path(jsonl_raw)
        os.close(jsonl_fd)
        jsonl_fd = None
        os.environ["PKCS11_CHECK_REPORT_LOG"] = jsonl_raw
        if disabled_nodeids:
            deselect_path = write_deselect_file(disabled_nodeids)
            os.environ["PKCS11_CHECK_DESELECT_FILE"] = str(deselect_path)
        exit_code = pytest.main(args)
        restore_caller_environment()
        if deselect_path is not None:
            with suppress(Exception):
                deselect_path.unlink(missing_ok=True)
        assert jsonl_path is not None
        completion_verified = _ensure_nonisolated_completion_record(
            jsonl_path,
            returncode=int(exit_code),
            stdout="",
            stderr="",
        )
        assembled_payload: dict[str, Any] | None = None
        if output == "json" and jsonl_path is not None:
            assembled_payload = _assemble_json_artifacts_from_jsonl(
                jsonl_path,
                output_file,
                run_provenance,
                returncode=int(exit_code),
                completion_verified=completion_verified,
            )
        elif jsonl_path is not None:
            detail = _build_detail_from_report_records(iter_report_log_records(jsonl_path))
            jsonl_path.unlink(missing_ok=True)
            if not completion_verified and output == "rich":
                console.print(
                    f"[red]INCOMPLETE[/red] non-isolated pytest run: report log completion "
                    f"could not be verified for raw exit code {exit_code}"
                )
            if not completion_verified and output == "junit":
                report_target = "<non-isolated>"
                report_detail = detail or {"counts": {}, "tests": []}
                counts = report_detail.get("counts", {})
                if isinstance(counts, Mapping) and counts.get("timeout", 0) > 0:
                    report_status = "timeout"
                elif isinstance(counts, Mapping) and counts.get("crashed", 0) > 0:
                    report_status = "crashed"
                elif isinstance(counts, Mapping) and counts.get("failed", 0) > 0:
                    report_status = "failed"
                else:
                    report_status = "passed"
                report_state = FileRunState(
                    units=[report_target],
                    fingerprint="",
                    results=[
                        FileRunResult(
                            target=report_target,
                            status=report_status,
                            returncode=int(exit_code),
                            duration_s=0.0,
                            completion_verified=False,
                        )
                    ],
                )
                write_isolated_junit_report(
                    Path(output_file or "pkcs11-check-results.xml"),
                    report_state,
                    per_unit_details={report_target: report_detail},
                )
        raw_exit_code = int(exit_code)
        public_exit_code = raw_exit_code if raw_exit_code in {0, 1} else 1
        if raw_exit_code in {2, 3, 4, 5}:
            public_exit_code = 2
        if raw_exit_code in {0, 1, 5} and not completion_verified:
            public_exit_code = 1
        if raw_exit_code in {2, 3, 4}:
            summary = assembled_payload.get("summary") if assembled_payload is not None else None
            provider_finding = isinstance(summary, Mapping) and any(
                int(summary.get(key, 0) or 0) > 0 for key in ("failed", "crashed", "timeout")
            )
            if assembled_payload is None:
                counts = detail.get("counts") if isinstance(detail, Mapping) else None
                provider_finding = isinstance(counts, Mapping) and any(
                    int(counts.get(key, 0) or 0) > 0 for key in ("failed", "crashed", "timeout")
                )
            if provider_finding:
                public_exit_code = 1
        raise typer.Exit(code=public_exit_code)
    finally:
        cleanup_owned_resources()
