#!/usr/bin/env python3
"""Compare two pkcs11-check JSON result files and report regressions.

Usage:
    uv run python scripts/compare-results.py baseline.json current.json
    uv run python scripts/compare-results.py baseline.json current.json --verbose

Exit codes:
    0 — no regressions
    1 — regressions found (new failures, crashes, or count changes)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_FAILURE_STATUSES = {"failed", "error", "crashed", "timeout"}


def _load_results(path: Path) -> tuple[dict[str, str], dict[str, int]]:
    """Load results JSON, return (target→status map, summary dict)."""
    data = json.loads(path.read_text())
    units = data.get("units", [])
    target_map: dict[str, str] = {}
    for unit in units:
        target = unit.get("target", "")
        status = unit.get("status", "unknown")
        target_map[target] = status
    summary = data.get("summary", {})
    return target_map, summary


def _status_class(status: str) -> str:
    if status in _FAILURE_STATUSES:
        return "failure"
    if status in ("skipped", "empty", "escalated", "crash_limited"):
        return "skipped"
    if status in ("xfailed", "xpassed"):
        return "xfail"
    return "pass"


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare pkcs11-check result files")
    parser.add_argument("baseline", type=Path, help="Baseline results JSON")
    parser.add_argument("current", type=Path, help="Current results JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show details")
    args = parser.parse_args()

    for p in (args.baseline, args.current):
        if not p.exists():
            print(f"Error: {p} not found", file=sys.stderr)
            return 1

    base_map, base_summary = _load_results(args.baseline)
    curr_map, curr_summary = _load_results(args.current)

    new_failures: list[str] = []
    new_passes: list[str] = []
    new_skips: list[str] = []
    status_changes: list[tuple[str, str, str]] = []

    all_targets = sorted(set(base_map) | set(curr_map))
    for target in all_targets:
        base_status = base_map.get(target, "absent")
        curr_status = curr_map.get(target, "absent")

        if base_status == curr_status:
            continue
        if base_status == "absent":
            if curr_status in _FAILURE_STATUSES:
                new_failures.append(target)
            else:
                status_changes.append((target, base_status, curr_status))
            continue
        if curr_status == "absent":
            status_changes.append((target, base_status, curr_status))
            continue

        base_cls = _status_class(base_status)
        curr_cls = _status_class(curr_status)

        if curr_cls == "failure" and base_cls != "failure":
            new_failures.append(target)
        elif base_cls == "failure" and curr_cls == "pass":
            new_passes.append(target)
        elif curr_cls == "skipped" and base_cls != "skipped":
            new_skips.append(target)
        else:
            status_changes.append((target, base_status, curr_status))

    has_regressions = bool(new_failures)

    print("=== Result Comparison ===")
    print(f"Baseline: {args.baseline.name}")
    print(f"Current:  {args.current.name}")
    print()

    base_total = base_summary.get("total", len(base_map))
    curr_total = curr_summary.get("total", len(curr_map))
    base_pass = base_summary.get("passed", 0)
    curr_pass = curr_summary.get("passed", 0)
    base_fail = sum(base_summary.get(k, 0) for k in ("failed", "error", "crashed", "timeout"))
    curr_fail = sum(curr_summary.get(k, 0) for k in ("failed", "error", "crashed", "timeout"))
    base_skip = base_summary.get("skipped", 0)
    curr_skip = curr_summary.get("skipped", 0)

    print("Summary:")
    print(f"  Total tests: {base_total} -> {curr_total} ({curr_total - base_total:+d})")
    print(f"  Passed:      {base_pass} -> {curr_pass} ({curr_pass - base_pass:+d})")
    print(f"  Failed:      {base_fail} -> {curr_fail} ({curr_fail - base_fail:+d})")
    print(f"  Skipped:     {base_skip} -> {curr_skip} ({curr_skip - base_skip:+d})")

    if new_failures:
        print(f"\nNEW FAILURES ({len(new_failures)}):")
        for t in new_failures:
            base_s = base_map.get(t, "absent")
            print(f"  REGRESSION: {t}: {base_s} -> {curr_map[t]}")

    if new_passes:
        print(f"\nNEW PASSES ({len(new_passes)}):")
        for t in new_passes:
            print(f"  FIXED: {t}: {base_map[t]} -> {curr_map.get(t, 'absent')}")

    if new_skips:
        print(f"\nNEW SKIPS ({len(new_skips)}):")
        for t in new_skips:
            base_s = base_map.get(t, "absent")
            print(f"  {t}: {base_s} -> {curr_map[t]}")

    if args.verbose and status_changes:
        print(f"\nOTHER CHANGES ({len(status_changes)}):")
        for t, old, new in status_changes:
            print(f"  {t}: {old} -> {new}")

    if has_regressions:
        print(f"\nRESULT: REGRESSIONS DETECTED ({len(new_failures)} new failure(s))")
    else:
        print("\nRESULT: NO REGRESSIONS")

    return 1 if has_regressions else 0


if __name__ == "__main__":
    sys.exit(main())
