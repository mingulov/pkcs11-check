"""Merge artifacts from parallel shard runs into one combined result set.

A "shard" is one container/process that ran ``pkcs11-check test`` over a
*disjoint subset* of the test files (each against its own isolated PKCS#11
server/token). Combining their artifact directories reproduces the artifacts a
single full run would have produced:

- ``report.jsonl``  : concatenation of the shard JSONL files (record sets are
  disjoint by unit, so the union is the full record set), with a compatibility
  enrichment that copies teardown-only RV traces onto failed/xfail reports from
  older shard artifacts.
- ``results.json``  : summary counters summed, ``units`` lists concatenated.
- ``coverage.json`` : recomputed from the concatenated JSONL via the existing
  :func:`extract_coverage_from_jsonl`, which unions names and sums counts and
  is order-independent — so the merge is exact (a split→merge round-trip
  reproduces the original).
- ``quality.json``  : regenerated (it is a pure function of the merged results +
  coverage + records).

The merge logic is intentionally a thin orchestration over functions that
already exist in :mod:`pkcs11_check.core.file_runner`; the only genuinely new
behaviour is summing summaries, concatenating the per-unit lists, and preserving
failure-local RV trace visibility for shards produced before failed reports
carried their own trace.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from pkcs11_check.core.file_runner import (
    extract_coverage_from_jsonl,
    extract_quality_report_records_from_jsonl,
    postprocess_jsonl_to_unified,
    write_quality_json_report,
)
from pkcs11_check.core.run_metrics import RESULT_OUTCOME_KEYS
from pkcs11_check.testcases._subprocess_trace import extract_subprocess_rv_trace

_SUMMARY_KEYS = RESULT_OUTCOME_KEYS


def _concat_jsonl(paths: list[Path], output_path: Path) -> None:
    """Non-destructively concatenate JSONL files into ``output_path``.

    Unlike ``file_runner.write_report_jsonl`` this does NOT delete the sources
    (they are shard artifacts we want to keep), and it ensures a trailing
    newline between files so records never run together.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as out_fh:
        for src in paths:
            if not src.exists():
                continue
            with src.open("rb") as in_fh:
                shutil.copyfileobj(in_fh, out_fh)
            # Guard against a source file that does not end in a newline.
            if src.stat().st_size and not _ends_with_newline(src):
                out_fh.write(b"\n")


def _ends_with_newline(path: Path) -> bool:
    with path.open("rb") as fh:
        try:
            fh.seek(-1, 2)
        except OSError:
            return True  # empty file
        return fh.read(1) == b"\n"


def _record_needs_rv_trace(record: dict[str, Any]) -> bool:
    return record.get("outcome") == "failed" or record.get("wasxfail") is not None


def _user_property_names(record: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for prop in record.get("user_properties") or []:
        if isinstance(prop, (list, tuple)) and prop:
            names.add(str(prop[0]))
    return names


def _record_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return "\n".join(_record_text(v) for v in value.values())
    if isinstance(value, list):
        return "\n".join(_record_text(v) for v in value)
    return ""


def _rv_trace_props(record: dict[str, Any]) -> list[list[Any]]:
    props: list[list[Any]] = []
    current_trace_len = 0
    for prop in record.get("user_properties") or []:
        if not isinstance(prop, (list, tuple)) or len(prop) != 2:
            continue
        name, value = prop
        if name in {"pkcs11_rv_trace", "pkcs11_rv_trace_dropped"}:
            props.append([name, value])
            if name == "pkcs11_rv_trace":
                current_trace_len = len(value or []) if isinstance(value, list) else 0

    trace = extract_subprocess_rv_trace(_record_text(record.get("longrepr")))
    if trace and len(trace) > current_trace_len:
        props = [prop for prop in props if prop[0] != "pkcs11_rv_trace"]
        props.append(["pkcs11_rv_trace", trace])
    return props


def _stream_records(jsonl_path: Path) -> Iterator[dict[str, Any]]:
    """Yield parsed dict records from a JSONL file line-by-line (no load-all)."""
    with jsonl_path.open(encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                yield rec


def _apply_trace_promotion(
    record: dict[str, Any], trace_by_node: dict[str, list[list[Any]]]
) -> bool:
    """Promote the node's best trace onto a failed/xfail report. Returns True if
    the record was modified."""
    if record.get("$report_type", "TestReport") != "TestReport":
        return False
    if not _record_needs_rv_trace(record):
        return False
    trace_props = trace_by_node.get(str(record.get("nodeid", "")))
    if not trace_props:
        return False
    user_properties = record.setdefault("user_properties", [])
    if not isinstance(user_properties, list):
        return False
    existing = _user_property_names(record)
    changed = False
    for name, value in trace_props:
        if name not in existing:
            user_properties.append([name, value])
            changed = True
            continue
        for index, prop in enumerate(user_properties):
            if not isinstance(prop, (list, tuple)) or len(prop) != 2:
                continue
            existing_name, existing_value = prop
            if existing_name != name:
                continue
            if existing_value in (None, "", [], {}) and value not in (None, "", [], {}):
                user_properties[index] = [name, value]
                changed = True
            break
    return changed


def _promote_rv_traces_to_outcome_reports(jsonl_path: Path) -> None:
    """Copy teardown-only RV traces onto failed/xfail reports for old shard artifacts.

    Streamed in at most two passes so the full record set is never held in
    memory: pass 1 builds the per-node best trace; pass 2 streams once more,
    applying the promotion while writing a temp file and tracking whether
    anything actually changed. The temp is renamed over the original only if a
    promotion was applied, otherwise it is discarded (original left untouched).
    Output is byte-identical to the previous detect-then-rewrite implementation.
    """
    trace_by_node: dict[str, list[list[Any]]] = {}
    for record in _stream_records(jsonl_path):
        if record.get("$report_type", "TestReport") != "TestReport":
            continue
        nodeid = str(record.get("nodeid", ""))
        props = _rv_trace_props(record)
        if not nodeid or not props:
            continue
        current = trace_by_node.get(nodeid, [])
        current_trace_len = len(dict(current).get("pkcs11_rv_trace") or [])
        new_trace_len = len(dict(props).get("pkcs11_rv_trace") or [])
        if not current or new_trace_len > current_trace_len:
            trace_by_node[nodeid] = props

    if not trace_by_node:
        return

    tmp_path = jsonl_path.with_suffix(jsonl_path.suffix + ".tmp")
    changed = False
    with tmp_path.open("w", encoding="utf-8") as out_fh:
        for record in _stream_records(jsonl_path):
            if _apply_trace_promotion(record, trace_by_node):
                changed = True
            out_fh.write(json.dumps(record) + "\n")
    if changed:
        tmp_path.replace(jsonl_path)
    else:
        tmp_path.unlink(missing_ok=True)


def merge_results_payloads(
    payloads: list[dict[str, Any]],
    *,
    coverage: dict[str, Any] | None,
    shard_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Combine N ``results.json`` payloads (summary summed, units concatenated)."""
    summary: dict[str, int] = {key: 0 for key in _SUMMARY_KEYS}
    units: list[dict[str, Any]] = []
    for payload in payloads:
        psum = payload.get("summary", {}) or {}
        for key in _SUMMARY_KEYS:
            summary[key] += int(psum.get(key, 0) or 0)
        units.extend(payload.get("units", []) or [])
    summary["total"] = sum(summary[key] for key in _SUMMARY_KEYS)

    merged: dict[str, Any] = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": summary,
        "units": units,
    }
    if coverage:
        merged["coverage"] = coverage
    if shard_meta is not None:
        merged["shards"] = shard_meta
    return merged


def _load_shard_payload(shard_dir: Path, warnings: list[str]) -> dict[str, Any] | None:
    """Load a shard's ``results.json``, salvaging it from ``report.jsonl`` if needed.

    A shard is finalized by writing ``report.jsonl`` incrementally and
    ``results.json`` last; an OOM/kill between the two (the very pressure the
    bounded pool guards against) leaves a shard with real failed/crashed records
    in its JSONL but no — or a truncated — ``results.json``. Folding only the
    JSONL into the merged report while dropping such a shard from the summed
    summary would *hide findings* from the headline counts. So:

    - present and valid ``results.json`` → use it;
    - missing or corrupt ``results.json`` but a non-empty ``report.jsonl`` →
      reconstruct an equivalent summary/units payload from that JSONL and record
      a warning;
    - neither usable → record a warning so the loss is never silent.

    Any abnormality is appended to ``warnings`` for the caller to surface.
    """
    results_path = shard_dir / "results.json"
    report_path = shard_dir / "report.jsonl"

    if results_path.exists():
        try:
            data = json.loads(results_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            warnings.append(
                f"{shard_dir.name}: results.json unreadable ({exc.__class__.__name__}); "
                "reconstructing summary from report.jsonl"
            )
        else:
            if isinstance(data, dict):
                partial = data.get("partial")
                if isinstance(partial, dict):
                    completed = partial.get("completed_units", "?")
                    planned = partial.get("planned_units", "?")
                    reason = str(partial.get("reason", "partial shard results"))
                    warnings.append(
                        f"{shard_dir.name}: partial results ({completed}/{planned} "
                        f"units completed): {reason}"
                    )
                return data
            warnings.append(
                f"{shard_dir.name}: results.json is not an object; "
                "reconstructing summary from report.jsonl"
            )

    # results.json missing or corrupt: salvage from the shard's own JSONL.
    if report_path.exists():
        with tempfile.TemporaryDirectory() as tmp:
            payload = postprocess_jsonl_to_unified(report_path, Path(tmp) / "results.json")
        if payload is not None:
            total = int(payload.get("summary", {}).get("total", 0) or 0)
            if not results_path.exists() and total > 0:
                warnings.append(
                    f"{shard_dir.name}: results.json missing; reconstructed "
                    f"{total} outcomes from report.jsonl"
                )
            return payload

    if results_path.exists():
        # Corrupt results.json AND no salvageable report.jsonl: a genuine loss.
        warnings.append(
            f"{shard_dir.name}: results.json corrupt and report.jsonl missing/empty; "
            "shard findings LOST from the merged summary"
        )
    return None


def merge_shard_dirs(shard_dirs: list[Path], output_dir: Path) -> dict[str, Any]:
    """Merge the artifact directories of N shard runs into ``output_dir``.

    Each shard dir is expected to contain ``results.json`` and ``report.jsonl``
    (as produced by ``pkcs11-check test --output json``). Returns the merged
    ``results.json`` payload.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    report_paths = [d / "report.jsonl" for d in shard_dirs]
    merged_report = output_dir / "report.jsonl"
    _concat_jsonl(report_paths, merged_report)
    _promote_rv_traces_to_outcome_reports(merged_report)

    coverage = extract_coverage_from_jsonl(merged_report) if merged_report.exists() else None
    if coverage:
        (output_dir / "coverage.json").write_text(json.dumps(coverage, indent=2) + "\n")

    payloads: list[dict[str, Any]] = []
    files_per_shard: list[int] = []
    warnings: list[str] = []
    for d in shard_dirs:
        payload = _load_shard_payload(d, warnings)
        if payload is None:
            files_per_shard.append(0)
            continue
        payloads.append(payload)
        files_per_shard.append(len(payload.get("units", []) or []))

    for warning in warnings:
        print(f"[merge] WARNING: {warning}", file=sys.stderr)

    shard_meta = {
        "count": len(shard_dirs),
        "dirs": [d.name for d in shard_dirs],
        "files_per_shard": files_per_shard,
    }
    if warnings:
        shard_meta["warnings"] = list(warnings)
    merged = merge_results_payloads(payloads, coverage=coverage, shard_meta=shard_meta)
    (output_dir / "results.json").write_text(json.dumps(merged, indent=2) + "\n")

    records = (
        extract_quality_report_records_from_jsonl(merged_report) if merged_report.exists() else []
    )
    write_quality_json_report(
        output_dir / "quality.json",
        merged,
        coverage=coverage,
        report_log_records=records,
    )
    return merged
