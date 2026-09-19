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
    extract_quality_report_evidence_from_jsonl,
    extract_quality_report_records_from_jsonl,
    postprocess_jsonl_to_unified,
    write_quality_json_report,
)
from pkcs11_check.core.report_log import (
    iter_report_log_records as _iter_report_log_records,
)
from pkcs11_check.core.report_log import user_property_names as _user_property_names
from pkcs11_check.core.run_metrics import (
    RESULT_OUTCOME_KEYS,
    compute_child_subprocess_counts,
    run_is_incomplete,
)
from pkcs11_check.core.subprocess_trace import extract_subprocess_rv_trace
from pkcs11_check.core.test_selection import CaseSelection, load_case_selection

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
    """Yield parsed dict records from a JSONL file line-by-line (no load-all).

    Delegates to the shared binary-decode iterator (report_log.iter_report_log_records)
    rather than a text-mode `for line in fh` loop, so a single undecodable byte anywhere
    in the file only drops that one line instead of raising UnicodeDecodeError and losing
    every remaining record.
    """
    yield from _iter_report_log_records(jsonl_path)


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


def _stamp_selection_batch_id(
    units: Any,
    batch_id: str,
    *,
    conflict_label: str,
    shard_name: str | None = None,
    overwrite: bool = False,
) -> None:
    """Annotate each real unit with ``batch_id``, refusing an explicit conflict.

    The single definition of the ``::daemon-recovery-`` rule: those synthetic
    units stand for a confirmed daemon death, not for a collected test case, so
    they are never part of a case batch and are deliberately left unstamped.
    Every stamping site in this module goes through here so that rule has one
    definition.

    ``overwrite`` replaces an existing value instead of only filling a missing
    one; a truthy value that disagrees with ``batch_id`` is an error either way.
    """
    for unit in units or []:
        if not isinstance(unit, dict):
            continue
        target = str(unit.get("target", ""))
        if "::daemon-recovery-" in target:
            continue
        unit_batch = unit.get("selection_batch_id")
        if unit_batch and unit_batch != batch_id:
            location = f" in {shard_name}" if shard_name else ""
            raise ValueError(
                f"unit selection_batch_id {unit_batch} does not match "
                f"{conflict_label} {batch_id}{location}"
            )
        if overwrite:
            unit["selection_batch_id"] = batch_id
        else:
            unit.setdefault("selection_batch_id", batch_id)


def _validate_selection_payloads(
    payloads: list[dict[str, Any]],
    *,
    testcases_root: Path | None = None,
) -> list[CaseSelection]:
    """Validate selection metadata consistency across shard payloads."""
    selections: list[CaseSelection] = []
    for payload in payloads:
        raw_selection = payload.get("selection")
        if raw_selection is not None:
            if not isinstance(raw_selection, dict):
                raise ValueError(
                    f"invalid selection payload: expected dict, got {type(raw_selection).__name__}"
                )
            selection = CaseSelection.from_dict(raw_selection, testcases_root=testcases_root)
            selections.append(selection)
            _stamp_selection_batch_id(
                payload.get("units"),
                selection.batch_id,
                conflict_label="payload batch_id",
            )
        else:
            for unit in payload.get("units", []) or []:
                if isinstance(unit, dict) and unit.get("selection_batch_id"):
                    raise ValueError(
                        "unit has selection_batch_id but payload has no selection manifest"
                    )

    if selections:
        plan_ids = {s.plan_id for s in selections}
        if len(plan_ids) > 1:
            raise ValueError(
                f"conflicting selection plan IDs across merged shards: {sorted(plan_ids)}"
            )
        seen_batch_ids: set[str] = set()
        seen_nodeids: set[str] = set()
        for s in selections:
            if s.batch_id in seen_batch_ids:
                raise ValueError(f"duplicate selection batch ID in merge: {s.batch_id}")
            seen_batch_ids.add(s.batch_id)
            overlap = seen_nodeids.intersection(s.nodeids)
            if overlap:
                raise ValueError(
                    f"overlapping node IDs across selection batches in merge: {sorted(overlap)}"
                )
            seen_nodeids.update(s.nodeids)
    else:
        # F19: without selection manifests there is no node-level overlap check,
        # so a shard merged twice (or two overlapping --shard ranges) would
        # silently double-count summaries. Guard on unit targets instead. The
        # session-global pseudo-units (<collection>, <lifecycle>) legitimately
        # repeat in every shard, as do ::daemon-recovery- synthetics (one per
        # confirmed daemon death, never part of a case batch), so all are
        # excluded; every other duplicate target is a double-count.
        seen_targets: set[str] = set()
        for payload in payloads:
            shard_targets: set[str] = set()
            for unit in payload.get("units", []) or []:
                if not isinstance(unit, dict):
                    continue
                target = str(unit.get("target", ""))
                if (
                    not target
                    or target in {"<collection>", "<lifecycle>"}
                    or "::daemon-recovery-" in target
                ):
                    continue
                shard_targets.add(target)
            overlap = seen_targets.intersection(shard_targets)
            if overlap:
                raise ValueError(
                    "duplicate unit targets across merged shards "
                    f"(summaries would double-count): {sorted(overlap)}"
                )
            seen_targets.update(shard_targets)

    return selections


def merge_results_payloads(
    payloads: list[dict[str, Any]],
    *,
    coverage: dict[str, Any] | None,
    shard_meta: dict[str, Any] | None = None,
    incomplete_evidence: bool = False,
    testcases_root: Path | None = None,
) -> dict[str, Any]:
    """Combine N ``results.json`` payloads (summary summed, units concatenated)."""
    _validate_selection_payloads(payloads, testcases_root=testcases_root)

    summary: dict[str, int] = {key: 0 for key in _SUMMARY_KEYS}
    units: list[dict[str, Any]] = []
    incoming_incomplete = False
    for payload in payloads:
        psum = payload.get("summary", {}) or {}
        incoming_incomplete = incoming_incomplete or bool(psum.get("incomplete", False))
        for key in _SUMMARY_KEYS:
            summary[key] += int(psum.get(key, 0) or 0)
        units.extend(payload.get("units", []) or [])
    summary["total"] = sum(summary[key] for key in _SUMMARY_KEYS)
    child_crash, child_timeout = compute_child_subprocess_counts(units)
    summary["child_crash"] = child_crash
    summary["child_timeout"] = child_timeout
    summary["incomplete"] = incoming_incomplete or incomplete_evidence
    summary["incomplete"] = run_is_incomplete(summary, units)

    shard_provenance = [p["provenance"] for p in payloads if isinstance(p.get("provenance"), dict)]
    merged_provenance = shard_provenance[0] if shard_provenance else None
    if merged_provenance is not None and any(
        provenance != merged_provenance for provenance in shard_provenance[1:]
    ):
        raise ValueError("shard provenance differs; refusing to merge mismatched test inputs")
    merged: dict[str, Any] = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": summary,
        "units": units,
    }
    if merged_provenance:
        merged["provenance"] = merged_provenance
    if coverage:
        merged["coverage"] = coverage
    if shard_meta is not None:
        merged["shards"] = shard_meta
    return merged


def _recover_selection_from_sidecar(
    payload: dict[str, Any],
    sidecar_selection: CaseSelection,
    shard_dir: Path,
    warnings: list[str],
) -> None:
    """Recover batch membership from ``selection.json`` for a *salvaged* payload.

    Salvage only. An intact ``results.json`` proves its own membership: the
    framework emits the top-level ``selection`` block whenever
    ``--selection-manifest`` was honored, so a missing block there means the
    manifest never reached the child and the run covered the full source file.
    Where the payload could not be produced normally (corrupt/missing
    ``results.json``, or an externally salvaged ``partial`` payload) that
    self-proof does not exist, and the sidecar is the only membership evidence
    left — it records what the batch was *planned* to be, not that it was
    enforced. The recovery is therefore always warned, and every such payload is
    also marked incomplete by its caller.
    """
    payload["selection"] = sidecar_selection.to_dict()
    _stamp_selection_batch_id(
        payload.get("units"),
        sidecar_selection.batch_id,
        conflict_label="sidecar batch_id",
        shard_name=shard_dir.name,
        overwrite=True,
    )
    warnings.append(
        f"{shard_dir.name}: selection membership recovered from selection.json for a "
        f"salvaged payload; exact batch enforcement is unproven "
        f"(batch {sidecar_selection.batch_id})"
    )


def _load_shard_payload(
    shard_dir: Path,
    warnings: list[str],
    *,
    testcases_root: Path | None = None,
) -> dict[str, Any] | None:
    """Load a shard's ``results.json``, salvaging it from ``report.jsonl`` if needed.

    A shard is finalized by writing ``report.jsonl`` incrementally and
    ``results.json`` last; an OOM/kill between the two (the very pressure the
    bounded pool guards against) leaves a shard with real failed/crashed records
    in its JSONL but no — or a truncated — ``results.json``. Folding only the
    JSONL into the merged report while dropping such a shard from the summed
    summary would *hide findings* from the headline counts. So:

    - present and valid ``results.json`` → use it. Such a payload also proves its
      own case-batch membership: the framework emits the top-level ``selection``
      block whenever ``--selection-manifest`` was honored, so a missing block
      beside a ``selection.json`` sidecar means the manifest never reached the
      child (that run covered the full source file) and is an error, not
      something to be stamped from the sidecar;
    - missing or corrupt ``results.json`` but a non-empty ``report.jsonl`` →
      reconstruct an equivalent summary/units payload from that JSONL and record
      a warning. Only here (and for an externally salvaged ``partial`` payload)
      is batch membership recovered from the sidecar, warned as unproven;
    - neither usable → record a warning so the loss is never silent.

    Any abnormality is appended to ``warnings`` for the caller to surface.
    """
    results_path = shard_dir / "results.json"
    report_path = shard_dir / "report.jsonl"
    selection_path = shard_dir / "selection.json"

    sidecar_selection: CaseSelection | None = None
    if selection_path.exists():
        sidecar_selection = load_case_selection(selection_path, testcases_root=testcases_root)

    if results_path.exists():
        try:
            data = json.loads(results_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            warnings.append(
                f"{shard_dir.name}: results.json unreadable ({exc.__class__.__name__}); "
                "reconstructing summary from report.jsonl"
            )
        else:
            if isinstance(data, dict):
                partial = data.get("partial")
                # A ``partial`` block marks an externally salvaged payload (e.g.
                # docker/optee-pkcs11/salvage-artifacts.py rebuilding results.json from
                # state.json after the guest died). Such a payload parses as an object but
                # legitimately never carried the framework's own ``selection`` block.
                salvaged = isinstance(partial, dict)
                if isinstance(partial, dict):  # narrows for mypy
                    completed = partial.get("completed_units", "?")
                    planned = partial.get("planned_units", "?")
                    reason = str(partial.get("reason", "partial shard results"))
                    warnings.append(
                        f"{shard_dir.name}: partial results ({completed}/{planned} "
                        f"units completed): {reason}"
                    )
                    summary = data.setdefault("summary", {})
                    if isinstance(summary, dict):
                        summary["incomplete"] = True

                if sidecar_selection is not None:
                    if "selection" in data:
                        if data["selection"] != sidecar_selection.to_dict():
                            raise ValueError(
                                f"selection mismatch between results.json and "
                                f"selection.json in {shard_dir.name}"
                            )
                        _stamp_selection_batch_id(
                            data.get("units"),
                            sidecar_selection.batch_id,
                            conflict_label="sidecar batch_id",
                            shard_name=shard_dir.name,
                        )
                    elif salvaged:
                        # Salvaged payload: the run never got to emit its own proof, so
                        # membership can only come from the sidecar (see the helper).
                        _recover_selection_from_sidecar(
                            data, sidecar_selection, shard_dir, warnings
                        )
                    else:
                        raise ValueError(
                            f"results.json in {shard_dir.name} has no selection block but "
                            f"selection.json is present: the run did not honor "
                            f"--selection-manifest, so it executed the full source file "
                            f"instead of batch {sidecar_selection.batch_id}"
                        )
                elif "selection" in data:
                    if isinstance(data["selection"], dict):
                        parsed_sel = CaseSelection.from_dict(
                            data["selection"], testcases_root=testcases_root
                        )
                        _stamp_selection_batch_id(
                            data.get("units"),
                            parsed_sel.batch_id,
                            conflict_label="results.json selection batch_id",
                            shard_name=shard_dir.name,
                        )
                    else:
                        raise ValueError(
                            f"results.json selection is not a dict in {shard_dir.name}"
                        )
                return data
            warnings.append(
                f"{shard_dir.name}: results.json is not an object; "
                "reconstructing summary from report.jsonl"
            )

    # results.json missing or corrupt: salvage from the shard's own JSONL.
    # postprocess_jsonl_to_unified always returns a dict (never None). A zero-count salvage is
    # only a genuine loss when results.json *existed* (proof the shard ran) but was corrupt --
    # then an empty report.jsonl means the findings are gone; a simply-missing results.json with
    # an empty JSONL is treated as "shard produced nothing", not a loss.
    if report_path.exists():
        with tempfile.TemporaryDirectory() as tmp:
            payload = postprocess_jsonl_to_unified(report_path, Path(tmp) / "results.json")
        payload["summary"]["incomplete"] = True
        total = int(payload.get("summary", {}).get("total", 0) or 0)
        if not results_path.exists() and total > 0:
            warnings.append(
                f"{shard_dir.name}: results.json missing; reconstructed "
                f"{total} outcomes from report.jsonl"
            )
        elif results_path.exists() and total == 0:
            warnings.append(
                f"{shard_dir.name}: results.json corrupt and report.jsonl empty; "
                "shard findings LOST from the merged summary"
            )
        if sidecar_selection is not None:
            _recover_selection_from_sidecar(payload, sidecar_selection, shard_dir, warnings)
        return payload

    if results_path.exists():
        # Corrupt results.json AND no salvageable report.jsonl: a genuine loss.
        warnings.append(
            f"{shard_dir.name}: results.json corrupt and report.jsonl missing/empty; "
            "shard findings LOST from the merged summary"
        )
    else:
        warnings.append(
            f"{shard_dir.name}: results.json and report.jsonl missing; "
            "shard findings LOST from the merged summary"
        )
    if sidecar_selection is not None:
        synthetic: dict[str, Any] = {
            "tool": "pkcs11-check",
            "kind": "test-run",
            "summary": {"incomplete": True, "total": 0},
            "units": [],
        }
        _recover_selection_from_sidecar(synthetic, sidecar_selection, shard_dir, warnings)
        return synthetic
    return None


def merge_shard_dirs(
    shard_dirs: list[Path],
    output_dir: Path,
    *,
    testcases_root: Path | None = None,
) -> dict[str, Any]:
    """Merge the artifact directories of N shard runs into ``output_dir``.

    Each shard dir is expected to contain ``results.json`` and ``report.jsonl``
    (as produced by ``pkcs11-check test --output json``). Returns the merged
    ``results.json`` payload.
    """
    payloads: list[dict[str, Any]] = []
    files_per_shard: list[int] = []
    warnings: list[str] = []
    for d in shard_dirs:
        payload = _load_shard_payload(d, warnings, testcases_root=testcases_root)
        if payload is None:
            files_per_shard.append(0)
            continue
        payloads.append(payload)
        files_per_shard.append(len(payload.get("units", []) or []))

    # Cross-shard validation BEFORE any output writes or concatenation:
    _validate_selection_payloads(payloads, testcases_root=testcases_root)

    shard_provenance = [p["provenance"] for p in payloads if isinstance(p.get("provenance"), dict)]
    merged_provenance = shard_provenance[0] if shard_provenance else None
    if merged_provenance is not None and any(
        provenance != merged_provenance for provenance in shard_provenance[1:]
    ):
        raise ValueError("shard provenance differs; refusing to merge mismatched test inputs")

    output_dir.mkdir(parents=True, exist_ok=True)

    report_paths = [d / "report.jsonl" for d in shard_dirs]
    merged_report = output_dir / "report.jsonl"
    # Classification observability is read from these per-shard raw sources -- each one
    # declared separately (not the single concatenated `merged_report`) for two reasons:
    # (1) a shard whose report.jsonl is missing is then a genuine missing declared source
    # (-> "partial"/lower-bound), which reading only the concatenated file could never
    # detect, since `_concat_jsonl` silently skips an absent shard file; (2) each path gets
    # its own fresh marker-provenance scope (per the shared contract's "reset marker
    # provenance at shard/session boundaries"), instead of one shard's trailing
    # IsolatedUnitReport marker leaking into the next shard's leading records. These files
    # are also untouched by the repair below -- `_promote_rv_traces_to_outcome_reports`
    # only ever rewrites `merged_report` -- so this read is authoritative and pre-repair by
    # construction; it must run independent of (and is safe to run before) that repair,
    # which silently drops any malformed line on rewrite and would otherwise make a
    # repaired, no-longer-authoritative stream look "complete". Pooled quality always
    # regenerates from these raw sources -- never from summed shard quality.json counts.
    quality_report_evidence = extract_quality_report_evidence_from_jsonl(report_paths)
    _concat_jsonl(report_paths, merged_report)
    _promote_rv_traces_to_outcome_reports(merged_report)

    coverage = extract_coverage_from_jsonl(merged_report) if merged_report.exists() else None
    if coverage:
        (output_dir / "coverage.json").write_text(
            json.dumps(coverage, indent=2) + "\n", encoding="utf-8"
        )

    for warning in warnings:
        print(f"[merge] WARNING: {warning}", file=sys.stderr)

    shard_meta = {
        "count": len(shard_dirs),
        "dirs": [d.name for d in shard_dirs],
        "files_per_shard": files_per_shard,
    }
    if warnings:
        shard_meta["warnings"] = list(warnings)
    merged = merge_results_payloads(
        payloads,
        coverage=coverage,
        shard_meta=shard_meta,
        incomplete_evidence=bool(warnings),
        testcases_root=testcases_root,
    )
    (output_dir / "results.json").write_text(
        json.dumps(merged, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    records = (
        extract_quality_report_records_from_jsonl(merged_report) if merged_report.exists() else []
    )
    write_quality_json_report(
        output_dir / "quality.json",
        merged,
        coverage=coverage,
        report_log_records=records,
        quality_report_evidence=quality_report_evidence,
    )
    return merged
