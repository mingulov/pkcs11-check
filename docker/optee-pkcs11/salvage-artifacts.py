#!/usr/bin/env python3
"""Reconstruct partial OP-TEE artifacts after an abrupt guest runner death.

The OP-TEE guest writes ``state.json`` and per-unit report-log shards while the
run is in progress. If the guest kernel OOM-kills the top-level Python runner,
the runner never reaches its finalizer and therefore never writes
``results.json``/``report.jsonl``/``quality.json``. This helper runs on the host
side of the OP-TEE Docker image and rebuilds partial artifacts from the completed
units only. It is deliberately dependency-free: the host side of the image is
not the guest Python site-packages environment.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

DETAIL_COUNT_KEYS = (
    "passed",
    "failed",
    "skipped",
    "xfailed",
    "xpassed",
    "error",
    "crashed",
    "timeout",
)
SPECIAL_STATUSES = {"failed", "crashed", "timeout"}


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return []

    records: list[dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def _cache_path(artifact_dir: Path, unit: str) -> Path:
    digest = hashlib.sha256(unit.encode("utf-8")).hexdigest()
    return artifact_dir / ".state.json.report-records" / f"{digest}.jsonl"


def _map_outcome(raw_outcome: str, wasxfail: Any) -> str:
    if raw_outcome == "passed" and wasxfail is not None:
        return "xpassed"
    if raw_outcome == "skipped" and wasxfail is not None:
        return "xfailed"
    return raw_outcome


def _flatten_longrepr(value: Any) -> str:
    if value in (None, "", [], {}):
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except TypeError:
        return str(value)


def _empty_counts() -> dict[str, int]:
    return {key: 0 for key in DETAIL_COUNT_KEYS}


def _detail_from_records(records: list[dict[str, Any]]) -> dict[str, Any] | None:
    counts = _empty_counts()
    tests: list[dict[str, Any]] = []
    skip_reasons: dict[str, int] = {}
    seen_call: set[str] = set()
    setup_events: list[dict[str, Any]] = []

    for record in records:
        if record.get("$report_type", "TestReport") != "TestReport":
            continue
        when = str(record.get("when", ""))
        if when == "setup":
            setup_events.append(record)
            continue
        if when != "call":
            continue
        nodeid = str(record.get("nodeid", "")).strip()
        seen_call.add(nodeid)
        outcome = _map_outcome(str(record.get("outcome", "passed")), record.get("wasxfail"))
        if outcome not in counts:
            outcome = "error"
        counts[outcome] += 1

        if outcome == "skipped":
            reason = _flatten_longrepr(record.get("longrepr")) or "skipped"
            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
            continue
        if outcome == "passed":
            continue

        entry: dict[str, Any] = {
            "nodeid": nodeid,
            "outcome": outcome,
            "duration": record.get("duration", 0.0),
        }
        if record.get("wasxfail") is not None:
            entry["wasxfail"] = record["wasxfail"]
        longrepr = _flatten_longrepr(record.get("longrepr"))
        if longrepr:
            entry["longrepr"] = longrepr
        tests.append(entry)

    seen_error_reprs: set[str] = set()
    for record in setup_events:
        nodeid = str(record.get("nodeid", "")).strip()
        if nodeid in seen_call:
            continue
        outcome = str(record.get("outcome", ""))
        if outcome == "skipped":
            counts["skipped"] += 1
            reason = _flatten_longrepr(record.get("longrepr")) or "skipped"
            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
            continue
        if outcome == "passed":
            continue

        counts["error"] += 1
        longrepr = _flatten_longrepr(record.get("longrepr"))
        dedup_key = longrepr or nodeid
        if dedup_key in seen_error_reprs:
            continue
        seen_error_reprs.add(dedup_key)
        entry = {
            "nodeid": nodeid,
            "outcome": "error",
            "duration": record.get("duration", 0.0),
        }
        if longrepr:
            entry["longrepr"] = longrepr
        tests.append(entry)

    if not any(counts.values()):
        return None
    detail: dict[str, Any] = {"counts": counts, "tests": tests}
    if skip_reasons:
        detail["skip_reasons"] = skip_reasons
    return detail


def _synthetic_detail_from_result(result: dict[str, Any]) -> dict[str, Any] | None:
    status = str(result.get("status", ""))
    if status not in SPECIAL_STATUSES:
        return None
    counts = _empty_counts()
    counts[status] = 1
    target = str(result.get("target", "unknown"))
    return {
        "counts": counts,
        "tests": [
            {
                "nodeid": target,
                "outcome": status,
                "longrepr": (
                    "synthetic OP-TEE salvage record: completed state entry had no "
                    "report-log cache"
                ),
            }
        ],
    }


def _normalize_result(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    target = raw.get("target")
    if not isinstance(target, str) or not target:
        return None
    return {
        "target": target,
        "status": str(raw.get("status", "unknown")),
        "returncode": int(raw.get("returncode", 0) or 0),
        "duration_s": float(raw.get("duration_s", 0.0) or 0.0),
        "stdout": str(raw.get("stdout", "") or ""),
        "stderr": str(raw.get("stderr", "") or ""),
    }


def _unit_payload(result: dict[str, Any], detail: dict[str, Any] | None) -> dict[str, Any]:
    status = str(result.get("status", "unknown"))
    unit: dict[str, Any] = {
        "target": result["target"],
        "status": status,
        "returncode": result["returncode"] if status in SPECIAL_STATUSES else 0,
        "duration_s": round(float(result.get("duration_s", 0.0)), 3),
    }
    if result.get("stdout"):
        unit["stdout"] = result["stdout"]
    if result.get("stderr"):
        unit["stderr"] = result["stderr"]
    if detail is not None:
        unit["counts"] = detail["counts"]
        if detail.get("tests"):
            unit["tests"] = detail["tests"]
        if detail.get("skip_reasons"):
            unit["skip_reasons"] = detail["skip_reasons"]
    return unit


def salvage_artifacts(artifact_dir: Path) -> bool:
    complete_artifacts = [
        artifact_dir / "results.json",
        artifact_dir / "report.jsonl",
        artifact_dir / "quality.json",
    ]
    if all(path.exists() and path.stat().st_size > 0 for path in complete_artifacts):
        print(f"OP-TEE artifact salvage: complete artifacts already exist in {artifact_dir}")
        return False

    state = _load_json(artifact_dir / "state.json")
    if state is None:
        print(f"OP-TEE artifact salvage: no readable state.json in {artifact_dir}")
        return False

    raw_results = state.get("results") or []
    results = [
        normalized
        for raw in raw_results
        if (normalized := _normalize_result(raw)) is not None
    ]
    if not results:
        print(f"OP-TEE artifact salvage: state has no completed units in {artifact_dir}")
        return False

    records_by_unit: dict[str, list[dict[str, Any]]] = {}
    for result in results:
        target = result["target"]
        records = _load_jsonl(_cache_path(artifact_dir, target))
        if records:
            records_by_unit[target] = records

    if records_by_unit:
        report_path = artifact_dir / "report.jsonl"
        with report_path.open("w", encoding="utf-8") as fh:
            for result in results:
                for record in records_by_unit.get(result["target"], []):
                    fh.write(json.dumps(record) + "\n")

    summary = _empty_counts()
    units: list[dict[str, Any]] = []
    for result in results:
        detail = _detail_from_records(records_by_unit.get(result["target"], []))
        if detail is None:
            detail = _synthetic_detail_from_result(result)
        if detail is not None:
            for key in DETAIL_COUNT_KEYS:
                summary[key] += int(detail["counts"].get(key, 0) or 0)
        units.append(_unit_payload(result, detail))
    summary["total"] = sum(summary.values())

    planned_units = len(state.get("units") or [])
    completed_units = len(results)
    payload: dict[str, Any] = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": summary,
        "units": units,
        "partial": {
            "reason": "OP-TEE guest runner exited before final report generation",
            "completed_units": completed_units,
            "planned_units": planned_units,
        },
    }
    (artifact_dir / "results.json").write_text(json.dumps(payload, indent=2) + "\n")

    quality = {
        "schema_version": "1",
        "selection_findings": [],
        "data_quality_warnings": [
            "partial OP-TEE artifact salvage",
            "selection telemetry not provided",
        ],
    }
    (artifact_dir / "quality.json").write_text(json.dumps(quality, indent=2) + "\n")

    print(
        "OP-TEE artifact salvage: wrote partial artifacts for "
        f"{completed_units}/{planned_units or '?'} completed units"
    )
    return True


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: salvage-artifacts.py ARTIFACT_DIR", file=sys.stderr)
        return 2
    artifact_dir = Path(argv[1])
    artifact_dir.mkdir(parents=True, exist_ok=True)
    salvage_artifacts(artifact_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
