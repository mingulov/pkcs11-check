"""Pure analysis helpers for quality audit artifacts."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, MutableMapping
from typing import Any, Literal, TypeAlias, cast

SchemaVersion: TypeAlias = str
SkipReasonCategory: TypeAlias = Literal[
    "missing_capability",
    "framework_constraint",
    "test_data_missing",
    "not_implemented",
    "unknown",
]

SCHEMA_VERSION: SchemaVersion = "1"
_PASSING_OUTCOMES = {"passed", "xpassed"}
_KNOWN_OUTCOMES = {"passed", "failed", "skipped", "xfailed", "xpassed", "error"}
_SELECTED_REASON_CATEGORY = {
    "missing_flags": "missing_capability",
    "missing_capability": "missing_capability",
    "missing_mechanism": "missing_capability",
    "missing_registry_config": "framework_constraint",
    "no_registry_config": "framework_constraint",
    "unsupported_multi_part": "framework_constraint",
    "missing_test_data": "test_data_missing",
    "not_implemented": "not_implemented",
}


def classify_skip_reason(reason: str | None) -> SkipReasonCategory:
    """Classify a free-text skip reason into a conservative category."""
    text = _normalize_reason_text(reason)
    if not text:
        return "unknown"

    lower = text.lower()

    if any(
        needle in lower
        for needle in (
            "not implemented",
            "not yet operational",
            "unimplemented",
            "future spec",
            "todo",
        )
    ):
        return "not_implemented"

    if any(
        needle in lower
        for needle in (
            "no --p11-module specified",
            "destructive test",
            "concurrent same-session test",
            "use --p11-destructive",
            "use --p11-thread-safe",
            "no mechanism catalog",
            "no registry config",
            "p11-kit not installed",
            "pkcs11-provider not installed",
            "no pin configured",
            "another user already logged in",
            "no token-present slots",
        )
    ):
        return "framework_constraint"

    if any(
        needle in lower
        for needle in (
            "not cloned",
            "missing test data",
            "missing vector",
            "vector file",
            "test vectors",
            "no cko_",
            "no ckh_",
            "no cko_profile objects present",
            "no cko_domain_parameters objects present",
            "no cko_hw_feature objects present",
            "no ckh_clock hardware feature objects present",
            "no ckh_monotonic_counter objects present",
            "no such file or directory",
            "file not found",
        )
    ):
        return "test_data_missing"

    if any(
        needle in lower
        for needle in (
            "not supported",
            "unsupported",
            "not available",
            "does not support",
            "mechanism ",
            "requires pkcs#11 v3",
            "module has v",
            "cannot generate",
            "cannot import",
            "mechanism not available",
            "curve ",
            "key pair generation not supported",
        )
    ):
        return "missing_capability"

    return "unknown"


def build_quality_audit(
    *,
    results: Mapping[str, Any] | None = None,
    coverage: Mapping[str, Any] | None = None,
    report_log_records: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a conservative quality audit from partial artifact data."""
    results_map = _mapping_or_empty(results)
    coverage_map = _mapping_or_empty(coverage)
    report_records = list(report_log_records or ())

    summary_counts = _build_summary_counts(results_map)
    explicit_outcomes, skip_buckets, warnings, explicit_test_count = _collect_results_details(
        results_map
    )
    report_outcomes, report_skip_buckets, report_test_count, report_warnings = (
        _collect_report_log_details(report_records, explicit_outcomes)
    )
    warnings.extend(report_warnings)
    _merge_outcomes(explicit_outcomes, report_outcomes)
    _merge_skip_buckets(skip_buckets, report_skip_buckets)

    selection_findings, selection_warning, selected_mechanisms = _collect_selection_findings(
        report_records, coverage_map
    )
    if selection_warning:
        warnings.append(selection_warning)

    mechanism_findings, mechanism_warning = _collect_mechanism_findings(
        coverage_map,
        selected_mechanisms,
    )
    if mechanism_warning:
        warnings.append(mechanism_warning)

    if not coverage_map:
        warnings.append("coverage.json not provided")
    if not report_records or not selection_findings:
        warnings.append("selection telemetry not provided")

    summary = {
        **summary_counts,
        "total": sum(summary_counts.values()),
        "units": _count_units(results_map),
        "test_records": explicit_test_count + report_test_count,
        "selection_scenarios": len(selection_findings),
        "mechanisms_available": len(_mechanism_available_names(coverage_map)),
        "mechanisms_invoked": len(_mechanism_invoked_names(coverage_map)),
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "summary": summary,
        "never_passed_nodeids": _sorted_never_passed_nodeids(explicit_outcomes),
        "framework_skip_candidates": _serialize_skip_buckets(skip_buckets),
        "selection_findings": selection_findings,
        "mechanism_findings": mechanism_findings,
        "data_quality_warnings": _dedupe_preserve_order(warnings),
    }


def _mapping_or_empty(value: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if value is None:
        return {}
    return value


def _normalize_reason_text(reason: str | None) -> str:
    if reason is None:
        return ""
    text = str(reason).strip()
    if not text:
        return ""
    if text.startswith("Skipped:"):
        text = text[len("Skipped:") :].strip()
    if "Skipped:" in text and text.startswith(("(", "[")):
        text = text.rsplit("Skipped:", 1)[-1].strip().rstrip("')\"]")
    return text


def _build_summary_counts(results: Mapping[str, Any]) -> dict[str, int]:
    summary = results.get("summary")
    counts = {name: 0 for name in _KNOWN_OUTCOMES}

    if isinstance(summary, Mapping):
        for name in counts:
            counts[name] = _coerce_int(summary.get(name), default=0)
        return counts

    units = results.get("units")
    if not isinstance(units, list):
        return counts

    for unit in units:
        if not isinstance(unit, Mapping):
            continue
        unit_counts = unit.get("counts")
        if not isinstance(unit_counts, Mapping):
            continue
        for name in counts:
            counts[name] += _coerce_int(unit_counts.get(name), default=0)
    return counts


def _collect_results_details(
    results: Mapping[str, Any],
) -> tuple[
    dict[str, set[str]],
    dict[tuple[str, str], dict[str, Any]],
    list[str],
    int,
]:
    outcomes_by_nodeid: dict[str, set[str]] = defaultdict(set)
    skip_buckets: dict[tuple[str, str], dict[str, Any]] = {}
    warnings: list[str] = []
    test_record_count = 0

    units = results.get("units")
    if not isinstance(units, list):
        return outcomes_by_nodeid, skip_buckets, warnings, test_record_count

    for unit in units:
        if not isinstance(unit, Mapping):
            warnings.append("results.json contains a non-mapping unit entry")
            continue

        tests = unit.get("tests")
        if isinstance(tests, list):
            for record in tests:
                if not isinstance(record, Mapping):
                    warnings.append("results.json contains a non-mapping test entry")
                    continue
                seen, _ = _observe_test_record(record, outcomes_by_nodeid, skip_buckets)
                if seen:
                    test_record_count += 1
        else:
            if unit.get("skip_reasons"):
                warnings.append(
                    "results.json unit lacks explicit test details; "
                    "using aggregated skip_reasons only"
                )

        skip_reasons = unit.get("skip_reasons")
        if isinstance(skip_reasons, Mapping):
            for raw_reason, raw_count in skip_reasons.items():
                reason = _normalize_reason_text(str(raw_reason))
                category = classify_skip_reason(reason)
                bucket = _ensure_skip_bucket(skip_buckets, reason, category)
                bucket["count"] += _coerce_int(raw_count, default=1)
                bucket["sources"].add("results.skip_reasons")

    if not outcomes_by_nodeid and not skip_buckets:
        warnings.append("results.json did not expose per-test details")

    return outcomes_by_nodeid, skip_buckets, warnings, test_record_count


def _collect_report_log_details(
    records: list[Mapping[str, Any]],
    seen_outcomes: dict[str, set[str]],
) -> tuple[dict[str, set[str]], dict[tuple[str, str], dict[str, Any]], int, list[str]]:
    outcomes_by_nodeid: dict[str, set[str]] = defaultdict(set)
    skip_buckets: dict[tuple[str, str], dict[str, Any]] = {}
    warnings: list[str] = []
    seen_keys: set[tuple[str, str, str]] = set()
    test_record_count = 0

    for record in records:
        if not isinstance(record, Mapping):
            warnings.append("report_log_records contains a non-mapping entry")
            continue
        if record.get("$report_type") != "TestReport":
            continue
        when = str(record.get("when", ""))
        if when not in {"call", "setup"}:
            continue

        nodeid = str(record.get("nodeid", "")).strip()
        outcome = _normalized_outcome(str(record.get("outcome", "")), record.get("wasxfail"))
        reason = _normalize_reason_text(_reason_text_from_record(record))
        key = (nodeid, outcome, reason)
        if nodeid in seen_outcomes and outcome in seen_outcomes[nodeid]:
            continue
        seen, _ = _observe_test_record(record, outcomes_by_nodeid, skip_buckets)
        if not seen:
            continue
        if key in seen_keys:
            continue

        seen_keys.add(key)
        test_record_count += 1
    return outcomes_by_nodeid, skip_buckets, test_record_count, warnings


def _observe_test_record(
    record: Mapping[str, Any],
    outcomes_by_nodeid: MutableMapping[str, set[str]],
    skip_buckets: MutableMapping[tuple[str, str], dict[str, Any]],
) -> tuple[bool, dict[str, Any] | None]:
    nodeid = str(record.get("nodeid", "")).strip()
    if not nodeid:
        return False, None

    outcome = _normalized_outcome(str(record.get("outcome", "")), record.get("wasxfail"))
    if outcome not in _KNOWN_OUTCOMES:
        return False, None

    outcomes_by_nodeid[nodeid].add(outcome)

    if outcome != "skipped":
        return True, None

    reason = _normalize_reason_text(_reason_text_from_record(record))
    category = classify_skip_reason(reason)
    bucket = _ensure_skip_bucket(skip_buckets, reason, category)
    bucket["count"] += 1
    bucket["nodeids"].add(nodeid)
    bucket["sources"].add("test_record")
    return True, bucket


def _reason_text_from_record(record: Mapping[str, Any]) -> str:
    longrepr = record.get("longrepr")
    if isinstance(longrepr, str):
        return longrepr
    if longrepr is None:
        return ""
    return str(longrepr)


def _normalized_outcome(outcome: str, wasxfail: Any) -> str:
    if outcome == "passed" and wasxfail is not None:
        return "xpassed"
    if outcome == "skipped" and wasxfail is not None:
        return "xfailed"
    return outcome


def _merge_outcomes(
    target: MutableMapping[str, set[str]],
    source: Mapping[str, set[str]],
) -> None:
    for nodeid, outcomes in source.items():
        target.setdefault(nodeid, set()).update(outcomes)


def _ensure_skip_bucket(
    buckets: MutableMapping[tuple[str, str], dict[str, Any]],
    reason: str,
    category: SkipReasonCategory,
) -> dict[str, Any]:
    key = (category, reason)
    bucket = buckets.get(key)
    if bucket is None:
        bucket = {
            "reason": reason,
            "category": category,
            "count": 0,
            "nodeids": set(),
            "sources": set(),
        }
        buckets[key] = bucket
    return bucket


def _merge_skip_bucket(
    target: MutableMapping[tuple[str, str], dict[str, Any]],
    bucket: Mapping[str, Any],
) -> None:
    key = (str(bucket["category"]), str(bucket["reason"]))
    merged = target.get(key)
    if merged is None:
        merged = {
            "reason": str(bucket["reason"]),
            "category": cast(SkipReasonCategory, str(bucket["category"])),
            "count": 0,
            "nodeids": set(),
            "sources": set(),
        }
        target[key] = merged
    merged["count"] += _coerce_int(bucket.get("count"), default=0)
    merged["nodeids"].update(bucket.get("nodeids", set()))
    merged["sources"].update(bucket.get("sources", set()))


def _merge_skip_buckets(
    target: MutableMapping[tuple[str, str], dict[str, Any]],
    source: Mapping[tuple[str, str], dict[str, Any]],
) -> None:
    for bucket in source.values():
        _merge_skip_bucket(target, bucket)


def _serialize_skip_buckets(
    buckets: Mapping[tuple[str, str], dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for bucket in sorted(
        buckets.values(),
        key=lambda item: (-_coerce_int(item.get("count"), default=0), str(item.get("reason", ""))),
    ):
        findings.append(
            {
                "reason": bucket["reason"],
                "category": bucket["category"],
                "count": _coerce_int(bucket.get("count"), default=0),
                "nodeids": sorted(str(nodeid) for nodeid in bucket.get("nodeids", set())),
                "sources": sorted(str(source) for source in bucket.get("sources", set())),
            }
        )
    return findings


def _sorted_never_passed_nodeids(outcomes_by_nodeid: Mapping[str, set[str]]) -> list[str]:
    never_passed = [
        nodeid
        for nodeid, outcomes in outcomes_by_nodeid.items()
        if outcomes and outcomes.isdisjoint(_PASSING_OUTCOMES)
    ]
    return sorted(never_passed)


def _collect_selection_findings(
    records: list[Mapping[str, Any]],
    coverage: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], str | None, dict[str, set[str]]]:
    selection_records = [
        record for record in records if record.get("$report_type") == "SelectionReport"
    ]
    if not selection_records:
        return [], None, {}

    invoked_names = _mechanism_invoked_names(coverage)
    coverage_has_invoked = bool(invoked_names)
    findings: list[dict[str, Any]] = []
    selected_mechanisms_by_scenario: dict[str, set[str]] = {}

    for record in selection_records:
        selection_coverage = record.get("selection_coverage")
        if not isinstance(selection_coverage, Mapping):
            return [], "selection telemetry missing selection_coverage payload", {}

        for scenario, raw_data in selection_coverage.items():
            if not isinstance(raw_data, Mapping):
                continue

            scenario_name = str(scenario)
            selected = _string_list(raw_data.get("selected_mechanisms"))
            rejected = _string_list(raw_data.get("rejected_mechanisms"))
            rejected_reason_counts = _string_counter(raw_data.get("rejected_reason_counts"))
            selected_mechanisms_by_scenario.setdefault(scenario_name, set()).update(selected)

            selected_but_not_invoked = (
                sorted(mech for mech in selected if mech not in invoked_names)
                if coverage_has_invoked
                else []
            )

            finding: dict[str, Any] = {
                "scenario": scenario_name,
                "selected_mechanisms": selected,
                "rejected_mechanisms": rejected,
                "selected_but_not_invoked": selected_but_not_invoked,
                "rejected_reason_counts": rejected_reason_counts,
                "rejected_reason_categories": _classify_reason_code_counts(rejected_reason_counts),
            }
            findings.append(finding)

    findings.sort(key=lambda item: str(item["scenario"]))
    return findings, None, selected_mechanisms_by_scenario


def _collect_mechanism_findings(
    coverage: Mapping[str, Any],
    selected_mechanisms_by_scenario: Mapping[str, set[str]],
) -> tuple[list[dict[str, Any]], str | None]:
    mechanism_coverage = coverage.get("mechanism_coverage")
    if not isinstance(mechanism_coverage, Mapping):
        return [], "coverage.json missing mechanism_coverage"

    available_names = _string_list(mechanism_coverage.get("available_names"))
    invoked_names = _string_list(mechanism_coverage.get("invoked_names"))
    not_invoked_names = _string_list(mechanism_coverage.get("not_invoked_names"))

    selected_to_scenarios: dict[str, list[str]] = defaultdict(list)
    for scenario, selected in selected_mechanisms_by_scenario.items():
        for mechanism in selected:
            selected_to_scenarios[mechanism].append(scenario)

    findings: list[dict[str, Any]] = []
    for mechanism in sorted(set(not_invoked_names) | set(selected_to_scenarios)):
        scenarios = sorted(selected_to_scenarios.get(mechanism, []))
        status = "selected_but_not_invoked" if scenarios else "not_invoked"
        if mechanism in invoked_names:
            status = "invoked"
        elif mechanism not in available_names and not scenarios:
            status = "unknown"
        findings.append(
            {
                "mechanism": mechanism,
                "status": status,
                "selected_in_scenarios": scenarios,
                "available": mechanism in available_names,
                "invoked": mechanism in invoked_names,
            }
        )

    return findings, None


def _classify_reason_code_counts(reason_counts: Mapping[str, int]) -> dict[str, int]:
    categories: Counter[str] = Counter()
    for code, count in reason_counts.items():
        categories[_classify_reason_code(str(code))] += _coerce_int(count, default=0)
    return dict(sorted(categories.items()))


def _classify_reason_code(code: str) -> SkipReasonCategory:
    return _SELECTED_REASON_CATEGORY.get(code, "unknown")


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items = [str(item) for item in value if item is not None]
    return sorted(dict.fromkeys(items))


def _string_counter(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    counter: Counter[str] = Counter()
    for key, item in value.items():
        counter[str(key)] += _coerce_int(item, default=0)
    return dict(sorted(counter.items()))


def _mechanism_available_names(coverage: Mapping[str, Any]) -> list[str]:
    mechanism_coverage = coverage.get("mechanism_coverage")
    if not isinstance(mechanism_coverage, Mapping):
        return []
    return _string_list(mechanism_coverage.get("available_names"))


def _mechanism_invoked_names(coverage: Mapping[str, Any]) -> list[str]:
    mechanism_coverage = coverage.get("mechanism_coverage")
    if not isinstance(mechanism_coverage, Mapping):
        return []
    return _string_list(mechanism_coverage.get("invoked_names"))


def _count_units(results: Mapping[str, Any]) -> int:
    units = results.get("units")
    if not isinstance(units, list):
        return 0
    return sum(1 for unit in units if isinstance(unit, Mapping))


def _coerce_int(value: Any, *, default: int) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _dedupe_preserve_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out
