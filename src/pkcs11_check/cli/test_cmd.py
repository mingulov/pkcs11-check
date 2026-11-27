"""pkcs11-check test command - run PKCS#11 test suite."""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
import tomllib
import uuid
from collections.abc import Mapping, Sequence
from contextlib import ExitStack, suppress
from dataclasses import replace as _dataclass_replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

import pytest
import typer
from pydantic import SecretStr
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from pkcs11_check import provenance as provenance_mod
from pkcs11_check.cli._choices import InterfaceChoice
from pkcs11_check.config import P11TestConfig
from pkcs11_check.config_layers import (
    find_ignored_settings,
    is_dead_config_key,
    read_toml_settings,
    resolve_config_rows,
)
from pkcs11_check.core._counters_durability import (
    COUNTERS_DIR_ENV,
    counters_run_dir_for_state,
    ensure_layout,
    prepare_resume,
    sweep_orphans,
    unseal,
)
from pkcs11_check.core._report_records import (
    _build_detail_from_report_records,
    _build_per_unit_details_from_record_sources,
    _seed_missing_report_record_caches_from_jsonl,
    _write_report_jsonl_from_record_sources,
)
from pkcs11_check.core._run_guard import RunArtifactsLockedError, run_artifact_guard
from pkcs11_check.core.call_counters import (
    ISOLATION_ENV,
    RUN_ID_ENV,
    CounterPersistenceError,
)
from pkcs11_check.core.collection import (
    CollectedPytestItem,
    CollectedSkip,
    collect_pytest_items_with_skips,
)
from pkcs11_check.core.collection_errors import (
    collection_failure_sidecar_path,
    ensure_failed_collection_report,
)
from pkcs11_check.core.counters_schema import mint_filename_nonce
from pkcs11_check.core.disabled_baseline import (
    build_disabled_baseline_block,
    format_disabled_baseline_banner,
    resolve_disabled_nodeids,
)
from pkcs11_check.core.doctor_probe import run_login_probe_subprocess
from pkcs11_check.core.file_runner import (
    FileRunResult,
    FileRunState,
    IsolatedReportConfig,
    _collection_failure_reporting_copy,
    _emit_external_provision_banner,
    _is_owned_counters_dir,
    _reset_fresh_run_artifacts,
    _resume_exit_code,
    _run_artifact_guard_paths,
    discover_auto_isolation_units,
    discover_pytest_units,
    extract_call_counters_from_jsonl,
    extract_coverage_from_jsonl,
    extract_provisioning_from_jsonl,
    extract_quality_report_evidence_from_jsonl,
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
from pkcs11_check.core.nodeids import normalize_nodeid
from pkcs11_check.core.preflight import (
    PREFLIGHT_EVIDENCE_ENV,
    PREFLIGHT_UNIT,
    PreflightCounters,
    preflight_evidence_path_for_state,
    run_preflight_subprocess,
)
from pkcs11_check.core.recovery import build_recovery_config
from pkcs11_check.core.report_log import SessionCompletionTracker, iter_report_log_records
from pkcs11_check.core.test_selection import (
    CaseSelection,
    DisabledSelectionPlan,
    _resolve_candidate_file,
    all_matched_items_disabled,
    build_disabled_selection_plan,
    get_testcases_root,
    load_case_selection,
    write_deselect_file,
)
from pkcs11_check.testcases.data import SOURCES_TOML, resolve_data_dir

console = Console(stderr=True)

_TESTCASES_DIR = str(Path(__file__).parent.parent / "testcases")

# H-12: mirrors P11TestConfig.key_inject's Literal. Provisioning treats any
# other value as unwrap, so the CLI rejects typos before anything runs.
_KEY_INJECT_MODES = frozenset({"off", "unwrap", "force-unwrap"})


def _preflight_timeout_seconds(test_timeout: int) -> int:
    return max(10, min(test_timeout, 60))


def _print_show_config(cli_values: dict[str, Any]) -> None:
    """Print effective value + source per config key (H-10, ``--show-config``).

    Goes to stdout (the deliverable), unlike the stderr diagnostics console.
    Secrets render as set/unset, never values.
    """
    rows = resolve_config_rows(
        cli_values=cli_values,
        env=os.environ,
        toml=read_toml_settings(),
    )
    table = Table(show_header=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Effective value")
    table.add_column("Source")
    for row in rows:
        # U13: dead keys live in docs/configuration.md, not in this table.
        # N3: keyed on deadness, never on the value text.
        if is_dead_config_key(row.key):
            continue
        # R18-4: rows are data, never markup -- a hostile value like
        # "[/red]" must render literally, never crash the table.
        table.add_row(escape(row.key), escape(row.effective), escape(row.source))
    Console().print(table)


def _unit_display_quiet(verbose: bool) -> bool:
    """U6: hide per-unit chatter unless verbose or DEBUG logging."""
    if verbose:
        return False
    return logging.getLogger().getEffectiveLevel() > logging.DEBUG


def _warn_ignored_sessions(sessions: int, isolation: str) -> None:
    """U13/N5: --sessions is dead in every mode; warn wherever passed."""
    if sessions != 1:
        console.print(
            f"[yellow]Warning:[/yellow] --sessions is ignored in --isolation {isolation} mode"
        )


def _print_run_totals(state_file: Path) -> None:
    """U5: end a text-mode run with unit totals (README 'Saving a report').

    Best-effort console line only: any state problem (missing, unreadable,
    or malformed) skips silently rather than disturbing the run verdict or
    exit path.
    """
    try:
        state = load_run_state(state_file)
        if state is None or not state.results:
            return
        counts: dict[str, int] = {}
        for result in state.results:
            counts[result.status] = counts.get(result.status, 0) + 1
        parts = ", ".join(f"{n} {status}" for status, n in sorted(counts.items()))
        console.print(f"Totals: {parts} ({len(state.results)} total)", markup=False)
    except Exception:  # noqa: BLE001  # M2: best-effort line must never mask the run exit
        return


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


def _new_run_id() -> str:
    """Return a fresh per-invocation run id (timestamp + pid + nonce).

    Format ``{UTC-microseconds}Z-p{pid}-{uuid4hex8}``. The timestamp+pid
    prefix stays readable and sortable (zero-padded fixed width, so
    lexicographic order matches creation order); the random nonce carries
    uniqueness, so a frozen clock or wall-clock rollback can never fuse two
    invocations. Timestamp+pid+random only, so no secret or
    machine-identifying material ever lands in the id.
    """
    nonce = uuid.uuid4().hex[:8]
    return f"{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}-p{os.getpid()}-{nonce}"


def splice_preflight_evidence(jsonl_path: Path, evidence_path: Path) -> int:
    """Append retained preflight scopes to a run JSONL; return scopes appended.

    A no-op returning 0 when either file is missing or the evidence is
    blank (no report was written, or the census never engaged). Raises
    ``OSError`` on I/O failure -- the caller warns, never fails the run.
    """
    if not jsonl_path.exists():
        return 0
    try:
        blob = evidence_path.read_bytes()
    except OSError:
        return 0
    if not blob.strip():
        return 0
    if not blob.endswith(b"\n"):
        blob += b"\n"
    with jsonl_path.open("rb+") as handle:
        handle.seek(0, 2)
        if handle.tell() > 0:
            handle.seek(-1, 2)
            if handle.read(1) != b"\n":
                handle.seek(0, 2)
                handle.write(b"\n")
        handle.seek(0, 2)
        handle.write(blob)
    return blob.count(b"SessionStart")


def refresh_results_call_counters(results_path: Path, jsonl_path: Path) -> bool:
    """Re-extract counters from a JSONL and patch ``results.json``; True when patched.

    Returns False when the JSONL holds no counter evidence (nothing to
    patch). Raises ``OSError``/``ValueError`` on unreadable/corrupt inputs --
    the caller warns, never fails the run.
    """
    payload = extract_call_counters_from_jsonl(jsonl_path)
    if payload is None:
        return False
    results = json.loads(results_path.read_text(encoding="utf-8"))
    if not isinstance(results, dict):
        raise ValueError(f"results file {results_path} is not a JSON object")
    results["call_counters"] = payload
    results_path.write_text(
        json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return True


def _evidence_counters(evidence_path: Path | None) -> dict[str, Any] | None:
    """Extract counters from a retained evidence file, else None (never raises)."""
    if evidence_path is None:
        return None
    try:
        if not evidence_path.exists() or not evidence_path.read_bytes().strip():
            return None
    except OSError:
        return None
    return extract_call_counters_from_jsonl(evidence_path)


def _write_early_failure_results(
    *,
    output: str,
    output_file: str | None,
    module: Path,
    status: str,
    legacy_returncode: int,
    observation: dict[str, Any] | None,
    case_selection: CaseSelection | None,
    preflight_evidence_path: Path | None,
) -> None:
    """Write results.json for a JSON run dead on arrival (exit 1), else nothing.

    Shared by the manifest-preflight and login-probe crash/timeout exits:
    exit 1 claims something happened, so the requested report must exist,
    marked incomplete, with the retained counter evidence folded in. Text
    mode and usage errors (exit 2) write nothing, as before.
    """
    if output != "json":
        return
    results_path = Path(output_file or "pkcs11-check-results.json")
    result = FileRunResult(
        target=str(module),
        status=status,
        returncode=legacy_returncode,
        duration_s=0.0,
    )
    state = FileRunState(
        units=[str(module)],
        fingerprint="",
        results=[result],
        process_observations=[observation] if isinstance(observation, dict) else [],
    )
    payload = write_isolated_json_report(
        results_path,
        state,
        selection=case_selection,
        call_counters=_evidence_counters(preflight_evidence_path),
    )
    payload["summary"]["incomplete"] = True
    results_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _retain_early_failure_evidence(
    *,
    output: str,
    output_file: str | None,
    preflight_evidence_path: Path | None,
    console: Console,
) -> None:
    """Retain counter-only JSONL evidence next to the results, else nothing.

    A dead-on-arrival JSON run keeps its counts-or-loss evidence even when
    no results file is written (plain error manifests); text mode and usage
    errors write nothing, as before.
    """
    if output != "json" or preflight_evidence_path is None:
        return
    try:
        blob = preflight_evidence_path.read_bytes()
    except OSError:
        blob = b""
    if blob.strip():
        report_path = Path(output_file or "pkcs11-check-results.json").parent
        report_path.mkdir(parents=True, exist_ok=True)
        try:
            (report_path / "report.jsonl").write_bytes(blob)
        except OSError as exc:
            console.print(
                f"[yellow]Warning:[/yellow] preflight counter evidence not retained: {exc}"
            )


def _fold_preflight_evidence(
    report_config: IsolatedReportConfig | None,
    evidence_path: Path | None,
    output: str,
    console: Console,
) -> None:
    """Splice retained preflight scopes into the merged report (isolated path).

    Appends every accumulated round's evidence to the merged ``report.jsonl``
    and, for JSON output, refreshes the ``call_counters`` block the runner
    extracted before the splice. Warns and continues on any failure: counter
    plumbing never fails a run.
    """
    if report_config is None or report_config.jsonl_path is None or evidence_path is None:
        return
    try:
        spliced = splice_preflight_evidence(report_config.jsonl_path, evidence_path)
    except OSError as exc:
        console.print(f"[yellow]Warning:[/yellow] preflight counter evidence not folded: {exc}")
        return
    if spliced == 0 or output != "json":
        return
    try:
        refresh_results_call_counters(report_config.output_path, report_config.jsonl_path)
    except (OSError, ValueError) as exc:
        console.print(f"[yellow]Warning:[/yellow] preflight counters not refreshed: {exc}")


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
    # NOTE: no wrap_key_value — KEK transport is env-only (P11TEST_WRAP_KEY_VALUE,
    # F-002). It must never appear on a child command line.
    wrap_mech: str | None,
    wrap_rsa_bits: int,
    wrap_oaep_hash: str,
    allow_external_provision: bool,
    external_provision_cmd: str | None,
    vendor_mechanism: list[str] | None,
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
    for spec in vendor_mechanism or []:
        args.extend(["--p11-vendor-mechanism", spec])
    if wrap_key_source != "bootstrap":
        args.extend(["--p11-wrap-key-source", wrap_key_source])
    if wrap_key_label is not None:
        args.extend(["--p11-wrap-key-label", wrap_key_label])
    if wrap_key_handle is not None:
        args.extend(["--p11-wrap-key-handle", str(wrap_key_handle)])
    # F-002: --p11-wrap-key-value is never emitted; children read P11TEST_WRAP_KEY_VALUE.
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


def _isolated_report_config(
    output: str,
    output_file: str | None,
    selection: CaseSelection | None = None,
) -> IsolatedReportConfig | None:
    if output not in {"json", "junit"}:
        return None
    if output == "json":
        results_path = Path(output_file or "pkcs11-check-results.json")
        jsonl_path = results_path.parent / "report.jsonl"
        return IsolatedReportConfig(
            "json", results_path, jsonl_path=jsonl_path, selection=selection
        )
    return IsolatedReportConfig(
        "junit", Path(output_file or "pkcs11-check-results.xml"), selection=selection
    )


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
        if not _reset_fresh_run_artifacts(state_file, report_config):
            # Reset refused: persist nothing, so the old run's retry
            # inputs survive (#88R44-[C]r6). The helper already
            # voiced the refusal; the caller still prints the
            # collection diagnostic and exits 2.
            return
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
            selection=report_config.selection,
            disabled_baseline=report_config.disabled_baseline,
        )
        write_quality_json_report(
            report_config.output_path.parent / "quality.json",
            payload,
            report_log_records=(
                extract_quality_report_records_from_jsonl(jsonl_path)
                if jsonl_path is not None
                else []
            ),
            quality_report_evidence=extract_quality_report_evidence_from_jsonl(
                [jsonl_path] if jsonl_path is not None else []
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
    # The single-run raw report.jsonl IS the declared authoritative source for this run's
    # classification observability.
    quality_report_evidence = extract_quality_report_evidence_from_jsonl([report_path])
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
        quality_report_evidence=quality_report_evidence,
    )
    return results_payload


def _validated_recorded_counters_dir(state_file: Path, recorded: str) -> Path:
    """Resolve a recorded counters dir, refusing non-allocated forms (M8).

    Resume reuses the state's recorded dir for evidence continuity, but a
    restored/planted state must never divert collection, sweep, and fence
    authority to an arbitrary directory: the recorded path must resolve to
    a sibling of the state file in an allocated counters-dir form
    (canonical or nonce-suffixed, same rule as fresh-run cleanup).
    """
    candidate = Path(recorded)
    resolved = candidate.resolve()
    if resolved.parent != state_file.resolve().parent or not _is_owned_counters_dir(
        state_file.name, resolved.name
    ):
        raise ValueError(
            f"recorded counters dir {recorded} is not an allocated counters dir "
            f"for state {state_file}"
        )
    return resolved


def test_command(
    module: Path = typer.Option(..., "--module", "-m", help="Path to PKCS#11 module"),
    interface: InterfaceChoice = typer.Option(
        "auto", "--interface", "-i", help="Interface version"
    ),
    sessions: int = typer.Option(
        1,
        "--sessions",
        "-s",
        help="Concurrent sessions (U13: dead knob, ignored; kept so old scripts still parse)",
        hidden=True,
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
    output: str = typer.Option(
        "rich", "--output", "-o", "--format", help="Output: rich, json, junit"
    ),
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
        help="Hex value of a symmetric configured KEK (prefer P11TEST_WRAP_KEY_VALUE env)",
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
    selection_manifest: Path | None = typer.Option(
        None,
        "--selection-manifest",
        help="Path to an exact case batch selection manifest",
        rich_help_panel="Selection",
    ),
    vendor_mechanism: list[str] | None = typer.Option(
        None,
        "--vendor-mechanism",
        metavar="NAME=0xID",
        help="Vendor mechanism code point, e.g. KMAC_128=0x80001234 (repeatable)",
        rich_help_panel="Selection",
    ),
    show_config: bool = typer.Option(
        False,
        "--show-config",
        help="Print effective config (value + source per key) and exit",
    ),
    targets: list[str] = typer.Argument(None, help="Optional pytest paths or nodeids"),
) -> None:
    """Run the PKCS#11 test suite against a module."""
    if show_config:
        # H-10: report-only; exits before validation, module checks, preflight.
        # log_level belongs to the global callback, so read back its effective
        # value from the root logger the callback already configured.
        # S12: same dead-setting warnings as a real run (parity, not silence).
        for ignored in find_ignored_settings(env=os.environ, toml=read_toml_settings()):
            console.print(f"[yellow]Warning:[/yellow] {ignored}")
        _warn_ignored_sessions(sessions, isolation)
        _print_show_config(
            {
                "module": str(module),
                "slot": slot,
                "interface": interface,
                "pin": pin,
                "so_pin": so_pin,
                "destructive": destructive,
                "log_level": logging.getLevelName(logging.getLogger().getEffectiveLevel()),
                "output": output,
                "rv_trace": rv_trace,
                "rv_trace_compact": rv_trace_compact,
                "key_inject": key_inject,
                "wrap_key_source": wrap_key_source,
                "wrap_key_label": wrap_key_label,
                "wrap_key_handle": wrap_key_handle,
                "wrap_key_value": wrap_key_value,
                "wrap_mech": wrap_mech,
                "wrap_rsa_bits": wrap_rsa_bits,
                "wrap_oaep_hash": wrap_oaep_hash,
                "allow_external_provision": allow_external_provision,
                "external_provision_cmd": external_provision_cmd,
            }
        )
        raise typer.Exit(code=0)
    if key_inject not in _KEY_INJECT_MODES:
        console.print(
            "[red]Error:[/red] invalid --key-inject "
            f"{key_inject!r}: expected off, unwrap, or force-unwrap"
        )
        raise typer.Exit(code=2)
    case_selection: CaseSelection | None = None
    if selection_manifest is not None:
        if output != "json":
            console.print("[red]Error:[/red] --selection-manifest requires --format json")
            raise typer.Exit(code=2)
        if isolation != "file":
            console.print("[red]Error:[/red] --selection-manifest requires --isolation file")
            raise typer.Exit(code=2)
        if not targets or len(targets) != 1 or "::" in targets[0]:
            console.print(
                "[red]Error:[/red] --selection-manifest requires exactly one bare file target"
            )
            raise typer.Exit(code=2)
        try:
            case_selection = load_case_selection(selection_manifest)
        except (ValueError, FileNotFoundError) as exc:
            console.print(f"[red]Error:[/red] invalid selection manifest: {exc}")
            raise typer.Exit(code=2) from exc

        target_str = targets[0]
        target_matches = False
        if target_str == case_selection.source or normalize_nodeid(target_str) == normalize_nodeid(
            case_selection.source
        ):
            target_matches = True
        else:
            try:
                root = get_testcases_root().resolve()
                expected_file = (root / case_selection.source).resolve()
                if _resolve_candidate_file(target_str, expected_file, root) == expected_file:
                    target_matches = True
            except (OSError, ValueError):
                pass
        if not target_matches:
            console.print(
                f"[red]Error:[/red] target {target_str!r} does not match manifest source "
                f"{case_selection.source!r}"
            )
            raise typer.Exit(code=2)

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

    # H-10: a provided-but-dead setting (documented layer that never applies)
    # warns instead of silently mis-scoping the run.
    for ignored in find_ignored_settings(env=os.environ, toml=read_toml_settings()):
        console.print(f"[yellow]Warning:[/yellow] {ignored}")

    original_pin = os.environ.get("P11TEST_PIN")
    had_original_pin = "P11TEST_PIN" in os.environ
    original_so_pin = os.environ.get("P11TEST_SO_PIN")
    had_original_so_pin = "P11TEST_SO_PIN" in os.environ
    original_wrap_key = os.environ.get("P11TEST_WRAP_KEY_VALUE")
    had_original_wrap_key = "P11TEST_WRAP_KEY_VALUE" in os.environ

    original_no_collection_cache = os.environ.get("PKCS11_CHECK_NO_COLLECTION_CACHE")
    had_no_collection_cache = "PKCS11_CHECK_NO_COLLECTION_CACHE" in os.environ
    original_deselect_file = os.environ.get("PKCS11_CHECK_DESELECT_FILE")
    had_deselect_file = "PKCS11_CHECK_DESELECT_FILE" in os.environ
    original_selection_manifest = os.environ.get("PKCS11_CHECK_SELECTION_MANIFEST")
    had_selection_manifest = "PKCS11_CHECK_SELECTION_MANIFEST" in os.environ
    original_isolation = os.environ.get(ISOLATION_ENV)
    had_original_isolation = ISOLATION_ENV in os.environ
    original_run_id = os.environ.get(RUN_ID_ENV)
    had_original_run_id = RUN_ID_ENV in os.environ
    original_preflight_evidence = os.environ.get(PREFLIGHT_EVIDENCE_ENV)
    had_preflight_evidence = PREFLIGHT_EVIDENCE_ENV in os.environ
    original_counters_dir = os.environ.get(COUNTERS_DIR_ENV)
    had_counters_dir = COUNTERS_DIR_ENV in os.environ
    manifest_path: Path | None = None
    manifest_fd: int | None = None
    jsonl_path: Path | None = None
    jsonl_fd: int | None = None
    deselect_path: Path | None = None
    preflight_evidence_path: Path | None = None
    # C1: the --isolation none counters tempdir, owned by this run and
    # removed in cleanup_owned_resources. Isolated runs use a retained
    # state sibling instead (resume continuity), never a temp.
    owned_counters_dir: Path | None = None
    # C2: the resume-barrier plan, computed before preflight and threaded
    # to the runner (None on fresh runs and --isolation none).
    counters_barrier_plan: dict[str, Any] | None = None
    # F-038: holds the run-artifact guards from before the first reset to
    # run end; entered once at startup, released in cleanup_owned_resources.
    artifact_guard_stack = ExitStack()

    def restore_caller_environment() -> None:
        if had_original_pin:
            os.environ["P11TEST_PIN"] = original_pin or ""
        else:
            os.environ.pop("P11TEST_PIN", None)
        if had_original_so_pin:
            os.environ["P11TEST_SO_PIN"] = original_so_pin or ""
        else:
            os.environ.pop("P11TEST_SO_PIN", None)
        if had_original_wrap_key:
            os.environ["P11TEST_WRAP_KEY_VALUE"] = original_wrap_key or ""
        else:
            os.environ.pop("P11TEST_WRAP_KEY_VALUE", None)
        if had_no_collection_cache:
            os.environ["PKCS11_CHECK_NO_COLLECTION_CACHE"] = original_no_collection_cache or ""
        else:
            os.environ.pop("PKCS11_CHECK_NO_COLLECTION_CACHE", None)
        if had_deselect_file:
            os.environ["PKCS11_CHECK_DESELECT_FILE"] = original_deselect_file or ""
        else:
            os.environ.pop("PKCS11_CHECK_DESELECT_FILE", None)
        if had_selection_manifest:
            os.environ["PKCS11_CHECK_SELECTION_MANIFEST"] = original_selection_manifest or ""
        else:
            os.environ.pop("PKCS11_CHECK_SELECTION_MANIFEST", None)
        if had_original_isolation:
            os.environ[ISOLATION_ENV] = original_isolation or ""
        else:
            os.environ.pop(ISOLATION_ENV, None)
        if had_original_run_id:
            os.environ[RUN_ID_ENV] = original_run_id or ""
        else:
            os.environ.pop(RUN_ID_ENV, None)
        if had_preflight_evidence:
            os.environ[PREFLIGHT_EVIDENCE_ENV] = original_preflight_evidence or ""
        else:
            os.environ.pop(PREFLIGHT_EVIDENCE_ENV, None)
        if had_counters_dir:
            os.environ[COUNTERS_DIR_ENV] = original_counters_dir or ""
        else:
            os.environ.pop(COUNTERS_DIR_ENV, None)

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
        # The none-path evidence temp is owned here; the isolated evidence
        # file is a retained state sibling and is never cleaned up.
        if isolation == "none" and preflight_evidence_path is not None:
            with suppress(Exception):
                preflight_evidence_path.unlink(missing_ok=True)
        # The none-path counters tempdir is likewise owned here (removed
        # whole); the isolated state sibling is retained for resume.
        if owned_counters_dir is not None:
            with suppress(Exception):
                shutil.rmtree(owned_counters_dir, ignore_errors=True)
        with suppress(Exception):
            artifact_guard_stack.close()

    try:
        # One run id per CLI invocation, seeded before preflight so the
        # census, recovery probes, and unit rounds all attribute to it. A
        # stale caller value is dropped first (saved above for restore), so
        # it can never be mistaken for this run's. Collection children
        # inherit the fresh id harmlessly: they have no report-log channel
        # and make no provider calls, so they emit nothing.
        os.environ.pop(RUN_ID_ENV, None)
        os.environ[RUN_ID_ENV] = _new_run_id()
        manifest_fd, manifest_raw_path = tempfile.mkstemp(
            prefix="pkcs11-check-manifest-",
            suffix=".json",
        )
        manifest_path = Path(manifest_raw_path)
        os.close(manifest_fd)
        manifest_fd = None

        if no_collection_cache:
            os.environ["PKCS11_CHECK_NO_COLLECTION_CACHE"] = "1"

        if case_selection is not None:
            results_path = Path(output_file or "pkcs11-check-results.json")
            results_path.parent.mkdir(parents=True, exist_ok=True)
            canonical_selection_path = results_path.parent / "selection.json"
            canonical_selection_path.write_text(
                case_selection.canonical_json() + "\n", encoding="utf-8"
            )
            os.environ["PKCS11_CHECK_SELECTION_MANIFEST"] = str(canonical_selection_path)

        # Pass PIN via env so pytest fixtures pick it up
        if pin:
            os.environ["P11TEST_PIN"] = pin
        if so_pin:
            os.environ["P11TEST_SO_PIN"] = so_pin
        # F-002: KEK likewise travels by env only, never on a command line.
        if wrap_key_value:
            os.environ["P11TEST_WRAP_KEY_VALUE"] = wrap_key_value

        # C2: the report layout is known before any provider work, so the
        # full guard set is computable here (the disabled-baseline block is
        # attached to a replaced copy later; the guarded paths never change).
        report_config = (
            _isolated_report_config(output, output_file, selection=case_selection)
            if isolation != "none"
            else None
        )

        # C2: hold every artifact guard from before the first reset to run
        # end (released in cleanup_owned_resources via the outer finally). A
        # run sharing any artifact with a live run refuses here, before it
        # can reset, allocate, fence, or write anything. Acquired once for
        # both modes; never nested.
        if isolation in {"auto", "file", "test"}:
            guard_paths = _run_artifact_guard_paths(state_file, report_config)
        elif output == "json":
            # Same guard discipline as the isolated path: the json layout
            # matches it exactly, so enumerate via a synthetic config.
            _none_results_path = Path(output_file or "pkcs11-check-results.json")
            guard_paths = _run_artifact_guard_paths(
                None,
                IsolatedReportConfig(
                    "json",
                    _none_results_path,
                    jsonl_path=_none_results_path.parent / "report.jsonl",
                ),
            )
        elif output == "junit":
            guard_paths = [Path(output_file or "pkcs11-check-results.xml")]
        else:
            guard_paths = []
        if guard_paths:
            try:
                artifact_guard_stack.enter_context(run_artifact_guard(*guard_paths))
            except RunArtifactsLockedError as exc:
                console.print(f"[red]Error:[/red] {exc}")
                raise typer.Exit(code=2) from exc

        # C1: the CLI allocates a run-owned counters dir on every
        # invocation, before preflight. Isolated runs use a state sibling
        # with a per-series nonce (covered by the state guard above);
        # --isolation none uses a fresh tempdir (owned, removed in
        # cleanup). Resume reuses the state's recorded dir for evidence
        # continuity (same precedence as the runner's: the recorded dir
        # wins). A stale caller export is dropped (saved above for
        # restore): the variable is child plumbing, not an opt-in, and
        # the census is always counted.
        if isolation == "none":
            counters_root = Path(tempfile.mkdtemp(prefix="pkcs11-check-counters-"))
            owned_counters_dir = counters_root
        else:
            recorded_counters_dir: str | None = None
            if resume:
                prior_counters_state = load_run_state(state_file)
                if prior_counters_state is not None:
                    stored = getattr(prior_counters_state, "counters_dir", None)
                    recorded_counters_dir = stored if isinstance(stored, str) else None
            if recorded_counters_dir:
                try:
                    counters_root = _validated_recorded_counters_dir(
                        state_file, recorded_counters_dir
                    )
                except ValueError as exc:
                    console.print(
                        f"[red]Error:[/red] refusing to resume: {exc}; re-run "
                        "without --resume for a fresh run (or restore the original directory)"
                    )
                    setup_exit_code = _resume_exit_code(state_file, 2)
                    raise typer.Exit(code=setup_exit_code) from exc
            else:
                # Fresh series (including resume-without-state): a new
                # run-specific dir, never a reused one (N-C3).
                counters_root = counters_run_dir_for_state(state_file, mint_filename_nonce())
        try:
            ensure_layout(counters_root)
        except CounterPersistenceError as exc:
            console.print(f"[red]Error:[/red] cannot create counters dir {counters_root}: {exc}")
            setup_exit_code = _resume_exit_code(state_file, 2) if resume else 2
            raise typer.Exit(code=setup_exit_code) from exc
        os.environ[COUNTERS_DIR_ENV] = str(counters_root)

        # C2: the durability barrier runs NOW, before any provider traffic.
        # Resume seals, collects, and fences old producers (the plan threads
        # to the runner, which applies it instead of re-running the barrier);
        # fresh runs lift a stale seal and sweep debris (the reset below then
        # clears the dir, so no dead series' evidence can fold into this one).
        # --isolation none skips it: its tempdir is born empty.
        if isolation != "none":
            if resume:
                prior_merged = report_config.jsonl_path if report_config is not None else None
                counters_barrier_plan = prepare_resume(
                    counters_root, prior_merged_jsonl=prior_merged
                )
                if not counters_barrier_plan.get("barrier_ok", False):
                    console.print(
                        "[red]Error:[/red] counter resume barrier failed; "
                        "refusing to run without proven quiescence "
                        "(re-run without --resume for a fresh series)"
                    )
                    setup_exit_code = _resume_exit_code(state_file, 2)
                    raise typer.Exit(code=setup_exit_code)
            else:
                try:
                    unseal(counters_root)
                except CounterPersistenceError:
                    pass
                swept = sweep_orphans(counters_root, current_run=os.environ[RUN_ID_ENV])
                if swept["retained"]:
                    console.print(
                        f"[dim]Counters dir holds {swept['retained']} unclaimed evidence "
                        f"file(s) from other runs (retained, not collected)[/dim]"
                    )

        if isolation in {"auto", "file", "test"}:
            preflight_evidence_path = preflight_evidence_path_for_state(state_file)
            if resume and not state_file.exists():
                # Resume-without-state only: stale rounds from an
                # unrelated run must not fold into this one. Fresh
                # runs delete after reset admission below
                # (#88R44-[C]r6), so a refused reset keeps its retry
                # inputs.
                preflight_evidence_path.unlink(missing_ok=True)
        else:
            evidence_fd, evidence_raw_path = tempfile.mkstemp(
                prefix="pkcs11-check-preflight-",
                suffix=".jsonl",
            )
            os.close(evidence_fd)
            preflight_evidence_path = Path(evidence_raw_path)
        if isolation in {"auto", "file", "test"} and not resume:
            # Remove stale output/state before any metadata collection can
            # fail (now also the counters dir + supplements, so a fresh
            # series cannot absorb a dead one's evidence). The isolated
            # runner repeats this reset when execution starts; keeping it
            # here closes the pre-run collection gap. On refusal the
            # run stops here (#88R44-[C]r6): the stale preflight
            # evidence below deletes only after reset admission, so a
            # refused reset keeps every retry input.
            if not _reset_fresh_run_artifacts(state_file, report_config):
                console.print(
                    "[red]Error:[/red] fresh-run reset refused (see the warning "
                    "above for the cause); state and reports left in place"
                )
                raise typer.Exit(code=2)
            preflight_evidence_path.unlink(missing_ok=True)

        assert manifest_path is not None
        assert preflight_evidence_path is not None
        census_counters = PreflightCounters(
            counters_dir=counters_root,
            run_id=os.environ[RUN_ID_ENV],
            unit=PREFLIGHT_UNIT,
            attempt=0,
            evidence_path=preflight_evidence_path,
        )
        # Recovery probes resolve the same file from the environment.
        os.environ[PREFLIGHT_EVIDENCE_ENV] = str(preflight_evidence_path)
        manifest = run_preflight_subprocess(
            module,
            interface=interface,
            slot=slot,
            timeout=_preflight_timeout_seconds(timeout),
            output_path=manifest_path,
            counters=census_counters,
        )
        if manifest.status != "ok":
            console.print(
                f"[red]Error:[/red] PKCS#11 preflight {manifest.status}: {manifest.error}"
            )
            if manifest.status in {"crashed", "timeout"}:
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
                _write_early_failure_results(
                    output=output,
                    output_file=output_file,
                    module=module,
                    status=manifest.status,
                    legacy_returncode=legacy_returncode,
                    observation=observation if isinstance(observation, dict) else None,
                    case_selection=case_selection,
                    preflight_evidence_path=preflight_evidence_path,
                )
            _retain_early_failure_evidence(
                output=output,
                output_file=output_file,
                preflight_evidence_path=preflight_evidence_path,
                console=console,
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

        # U1: fail fast on a wrong PIN (one login probe, one message) instead
        # of per-test login tracebacks. Only when a PIN was actually supplied
        # (CLI flag or env); other probe outcomes proceed to the run.
        effective_pin = pin or os.environ.get("P11TEST_PIN")
        if effective_pin:
            # Attempt 1 of the preflight unit: the same counters dir/run as
            # the manifest preflight (attempt 0), same evidence file, so the
            # probe's 8 calls join the session instead of vanishing.
            probe_counters = PreflightCounters(
                counters_dir=counters_root,
                run_id=os.environ[RUN_ID_ENV],
                unit=PREFLIGHT_UNIT,
                attempt=1,
                evidence_path=preflight_evidence_path,
            )
            login_probe = run_login_probe_subprocess(
                module,
                interface=interface,
                slot=slot,
                pin=effective_pin.encode("utf-8", "surrogateescape"),
                timeout=max(10, min(timeout, 60)),
                counters=probe_counters,
            )
            if login_probe.status == "pin_incorrect":
                console.print(
                    f"[red]✗[/red] PIN incorrect for slot {slot} — run `pkcs11-check doctor`"
                )
                raise typer.Exit(code=_resume_exit_code(state_file, 2) if resume else 2)
            if login_probe.status in {"crashed", "timeout"}:
                # A provider that dies or hangs on a single login cannot
                # produce a meaningful suite result; refusing to run beats a
                # green public-only finish that hides the crash. Omit --pin
                # to run login-independent tests without this gate.
                console.print(
                    f"[red]✗[/red] login probe {login_probe.status} for slot {slot}"
                    f" ({escape(login_probe.detail)}) — refusing to run the suite"
                )
                # Exit 1 claims something happened: the requested JSON report
                # must exist (R19-1), mirroring the manifest-crash artifacts.
                probe_returncode = (
                    124
                    if login_probe.status == "timeout"
                    else (login_probe.returncode if isinstance(login_probe.returncode, int) else 1)
                )
                _write_early_failure_results(
                    output=output,
                    output_file=output_file,
                    module=module,
                    status=login_probe.status,
                    legacy_returncode=probe_returncode,
                    observation=None,
                    case_selection=case_selection,
                    preflight_evidence_path=preflight_evidence_path,
                )
                _retain_early_failure_evidence(
                    output=output,
                    output_file=output_file,
                    preflight_evidence_path=preflight_evidence_path,
                    console=console,
                )
                raise typer.Exit(code=_resume_exit_code(state_file, 1) if resume else 1)
            if login_probe.status == "error":
                # The detail can carry child stderr (provider bytes): escape
                # it like every other hostile value (R18-4 class).
                console.print(
                    "[yellow]Warning:[/yellow] login probe inconclusive "
                    f"({escape(login_probe.detail)}) — proceeding anyway"
                )

        assert manifest_path is not None
        run_provenance = _build_run_provenance(manifest, resolve_data_dir())
        fw = run_provenance.get("framework") or {}
        fw_version = fw.get("version") or "?"
        if fw.get("source") == "git-describe":
            # U4: the describe suffix is truthful (computed live from this
            # checkout) but cryptic -- say once, in one clause, what it is.
            fw_version = f"{fw_version} (dev checkout)"
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
            wrap_mech=wrap_mech,
            wrap_rsa_bits=wrap_rsa_bits,
            wrap_oaep_hash=wrap_oaep_hash,
            allow_external_provision=allow_external_provision,
            external_provision_cmd=external_provision_cmd,
            vendor_mechanism=vendor_mechanism,
        )
        pytest_args.extend(["--p11-manifest", str(manifest_path)])

        # C2: report_config, the artifact guard, the counters dir, the
        # barrier, and the fresh reset all ran before preflight above; the
        # runner repeats the reset when execution starts (and applies the
        # threaded barrier plan instead of re-running the barrier).
        target_args = targets or [_TESTCASES_DIR]
        try:
            runtime_config = P11TestConfig(
                module=module,
                interface=interface,
                slot=slot,
                destructive=destructive,
                pin=SecretStr(pin) if pin is not None else None,
                # Validated against _KEY_INJECT_MODES at command entry (H-12).
                key_inject=cast(Literal["off", "unwrap", "force-unwrap"], key_inject),
                wrap_key_source=cast(Literal["bootstrap", "configured"], wrap_key_source),
                wrap_key_label=wrap_key_label,
                wrap_key_handle=wrap_key_handle,
                wrap_key_value=SecretStr(wrap_key_value) if wrap_key_value is not None else None,
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

        _warn_ignored_sessions(sessions, isolation)
        if isolation in {"auto", "file", "test"}:
            collection_phase = True

            try:
                collected_items = None
                collection_skips: list[CollectedSkip] | None = None
                auto_collected: list[CollectedPytestItem] | None = None
                if isolation == "auto":
                    prior_state = load_run_state(state_file) if resume else None
                    if prior_state is not None:
                        units = prior_state.units
                        collected_items, prior_skips = collect_pytest_items_with_skips(
                            target_args, pytest_args
                        )
                        collection_skips = prior_skips
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
                        auto_skips: list[CollectedSkip] = []
                        units = discover_auto_isolation_units(
                            target_args,
                            Path(_TESTCASES_DIR),
                            pytest_args=pytest_args,
                            policy_file=policy_file,
                            collected_out=auto_collected,
                            skips_out=auto_skips,
                        )
                        collected_items = auto_collected
                        collection_skips = auto_skips
                    runner_granularity: Literal["mixed"] | Literal["file", "test"] = "mixed"
                else:
                    isolated_mode = cast(Literal["file", "test"], isolation)
                    explicit_collected: list[CollectedPytestItem] | None = (
                        [] if isolated_mode == "test" and disabled_nodeids else None
                    )
                    explicit_skips: list[CollectedSkip] | None = (
                        [] if explicit_collected is not None else None
                    )
                    if explicit_collected is None:
                        units = discover_pytest_units(
                            target_args,
                            Path(_TESTCASES_DIR),
                            granularity=isolated_mode,
                            pytest_args=pytest_args,
                        )
                    else:
                        assert explicit_skips is not None
                        units = discover_pytest_units(
                            target_args,
                            Path(_TESTCASES_DIR),
                            granularity=isolated_mode,
                            pytest_args=pytest_args,
                            collected_out=explicit_collected,
                            skips_out=explicit_skips,
                        )
                    if explicit_collected is not None:
                        collected_items = explicit_collected
                        collection_skips = explicit_skips
                    runner_granularity = isolated_mode
                if disabled_nodeids:
                    if isolation == "auto":
                        if auto_collected is not None:
                            collected_items = auto_collected
                        else:
                            collected_items, plan_skips = collect_pytest_items_with_skips(
                                target_args, pytest_args
                            )
                            collection_skips = plan_skips
                    elif runner_granularity == "file":
                        collected_items, plan_skips = collect_pytest_items_with_skips(
                            target_args, pytest_args
                        )
                        collection_skips = plan_skips
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
                if disabled_nodeids:
                    # H-7 loud deselected-count reporting: excluded units never
                    # run and per-file deselections hide in child output, so
                    # print the banner and attach the machine-auditable block
                    # to results.json (via report_config; paths unchanged).
                    excluded_units = len(units) - len(selection_plan.units)
                    per_file_deselected = sum(
                        len(nodeids) for nodeids in selection_plan.deselect_by_file.values()
                    )
                    console.print(
                        "[yellow]"
                        + format_disabled_baseline_banner(
                            nodeid_count=len(disabled_nodeids),
                            excluded_units=excluded_units,
                            per_file_deselected=per_file_deselected,
                            fingerprint=selection_plan.baseline_fingerprint,
                        )
                        + "[/yellow]"
                    )
                    if report_config is not None:
                        report_config = _dataclass_replace(
                            report_config,
                            disabled_baseline=build_disabled_baseline_block(
                                fingerprint=selection_plan.baseline_fingerprint,
                                deselect_by_file=selection_plan.deselect_by_file,
                                excluded_units=excluded_units,
                            ),
                        )
                # U11: fail fast on an empty selection, before any unit runs.
                # Only when the user actually selected something (flags,
                # targets, or a selection manifest); full runs never probe.
                # Reuse already-collected metadata when the discovery path
                # produced it, else collect once here. M4: skip_slow /
                # only_slow count as selection (they can match nothing),
                # so filtered file/test runs pay one extra collection pass;
                # its only side effect is better unit timeouts (counts can
                # only raise the per-unit budget, never lower it).
                has_selection = bool(
                    match
                    or category
                    or marker
                    or skip_slow
                    or only_slow
                    or targets
                    or case_selection is not None
                )
                selected_count: int | None = None
                if has_selection:
                    if case_selection is not None:
                        selected_count = len(case_selection.nodeids)
                    elif collected_items is not None:
                        selected_count = len(collected_items)
                    else:
                        collected_items, gate_skips = collect_pytest_items_with_skips(
                            target_args, pytest_args
                        )
                        collection_skips = gate_skips
                        selected_count = len(collected_items)
                if (
                    selected_count == 0
                    or (not selection_plan.units and has_selection)
                    or (
                        bool(selected_count)
                        and bool(selection_plan.units)
                        and all_matched_items_disabled(collected_items, disabled_nodeids)
                    )
                ):
                    if selected_count and not selection_plan.units:
                        # M3: tests matched but every unit was excluded
                        # (e.g. the disabled baseline) -- say so exactly.
                        console.print(
                            "[red]Error:[/red] "
                            f"{selected_count} tests matched but all units were "
                            "excluded (nothing to run)"
                        )
                    elif selected_count and selection_plan.units:
                        # M3b: tests matched but the baseline excluded every
                        # matched node while a zero-match target file stayed
                        # scheduled -- running on would be vacuous.
                        console.print(
                            "[red]Error:[/red] "
                            f"{selected_count} tests matched but every matched test "
                            "was excluded (nothing to run)"
                        )
                    else:
                        console.print(
                            "[red]Error:[/red] 0 tests matched the selection (nothing to run)"
                        )
                        if collection_skips:
                            for skip in collection_skips[:10]:
                                console.print(
                                    f"  {escape(skip.nodeid)}: skipped at collection: "
                                    f"{escape(skip.reason)}"
                                )
                            if len(collection_skips) > 10:
                                console.print(
                                    f"  ...and {len(collection_skips) - 10} more "
                                    "skipped at collection"
                                )
                    empty_exit_code = _resume_exit_code(state_file, 2) if resume else 2
                    raise typer.Exit(code=empty_exit_code)
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
                if case_selection is not None:
                    selected_count = len(case_selection.nodeids)
                    unit_key = selection_plan.units[0] if selection_plan.units else targets[0]
                    runner_kwargs["unit_test_counts"] = {
                        unit_key: selected_count,
                        case_selection.source: selected_count,
                    }
                    runner_kwargs["selection_batch_id"] = case_selection.batch_id
                    runner_kwargs["selection_digest"] = case_selection.source_collection_sha256
                # Isolated path (fw#73): unit children read the flag value from
                # here (run_isolated_pytest_units copies os.environ); seeded late
                # so preflight/collection subprocesses do not inherit it. Restored
                # with the other run-scoped keys in restore_caller_environment.
                # The run id was seeded once before preflight and rides the same
                # bridge, so resume rounds stay attributable.
                os.environ[ISOLATION_ENV] = isolation
                exit_code = run_isolated_pytest_units(
                    selection_plan.units,
                    pytest_args,
                    quiet_unit_display=_unit_display_quiet(verbose),
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
                    counters_barrier_plan=counters_barrier_plan,
                    **runner_kwargs,
                )
                _fold_preflight_evidence(report_config, preflight_evidence_path, output, console)
                if output != "json":
                    _print_run_totals(state_file)
            except (FileNotFoundError, ValueError, CounterPersistenceError) as exc:
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
        # C2: the guard was acquired once at startup (same paths as the
        # isolated layout for json, the xml for junit, none for rich);
        # nothing to acquire here.
        jsonl_fd, jsonl_raw = tempfile.mkstemp(
            prefix="pkcs11-check-jsonl-",
            suffix=".jsonl",
            dir=str(results_path.parent) if output == "json" else None,
        )
        jsonl_path = Path(jsonl_raw)
        os.close(jsonl_fd)
        jsonl_fd = None
        # Explicit --report-log CLI arg (same two-arg spelling as the isolated
        # path): pytest-reportlog reads config.option.report_log eagerly in its
        # own pytest_configure, which on the observed/default installation runs
        # before ours (entry-point discovery order + pluggy LIFO hook
        # execution), so a late injection would miss the writer there.
        # Orthogonal to junit/rich modes.
        args.extend(["--report-log", str(jsonl_path)])
        # In-process none path (fw#73): the session record reads this directly.
        # Restored with the other run-scoped keys in restore_caller_environment.
        # The run id was seeded once before preflight (shared with the census).
        os.environ[ISOLATION_ENV] = "none"
        # C1: the in-process session runs disengaged (rc1 shape). Durability
        # sidecars would have no collecting parent -- a segfault kills the
        # CLI itself -- so the engagement keys go before pytest.main. The
        # census already ran engaged above; its evidence splices in below.
        # RUN_ID/ISOLATION stay for session attribution.
        os.environ.pop(COUNTERS_DIR_ENV, None)
        os.environ.pop(PREFLIGHT_EVIDENCE_ENV, None)
        if disabled_nodeids:
            deselect_path = write_deselect_file(disabled_nodeids)
            os.environ["PKCS11_CHECK_DESELECT_FILE"] = str(deselect_path)
            # H-7 loud deselected-count reporting (non-isolated path: every
            # baseline nodeid rides one deselect file; nothing pre-excluded).
            console.print(
                "[yellow]"
                + format_disabled_baseline_banner(
                    nodeid_count=len(disabled_nodeids),
                    excluded_units=0,
                    per_file_deselected=len(disabled_nodeids),
                    fingerprint=baseline_fingerprint,
                )
                + "[/yellow]"
            )
        exit_code = pytest.main(args)
        restore_caller_environment()
        if deselect_path is not None:
            with suppress(Exception):
                deselect_path.unlink(missing_ok=True)
        assert jsonl_path is not None
        if preflight_evidence_path is not None:
            try:
                splice_preflight_evidence(jsonl_path, preflight_evidence_path)
            except OSError as exc:
                console.print(
                    f"[yellow]Warning:[/yellow] preflight counter evidence not folded: {exc}"
                )
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
