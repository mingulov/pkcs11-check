"""Pure results-comparison logic for pkcs11-check.

Ported verbatim from scripts/compare-results.py with these targeted hardening changes:

1. ``status_class`` returns ``"unknown"`` for unrecognised statuses instead of silently
   falling through to ``"pass"``.  Dead legacy branches (``error``/``skipped``/
   ``xfailed``/``xpassed``) are removed; behaviour for all current unit statuses is
   identical to the original script.
2. Unknown statuses in either baseline or current are collected in
   ``ResultsComparison.unknown_statuses`` and included in ``has_regressions``
   (conservative: never silently pass an unrecognised status).
3. ``lost_coverage`` tracks ``status_class(base_status) == "pass"`` only (``"xfail"``
   class removed; no change for any real unit status).
4. No ``print`` / ``sys.exit`` — this is pure logic; the CLI task wires exit codes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any, Literal

StatusClass = Literal["failure", "skipped", "pass", "unknown"]

_FAILURE_STATUSES = frozenset({"failed", "crashed", "timeout"})
_SKIPPED_STATUSES = frozenset({"empty", "crash_limited", "escalated"})


def status_class(status: str) -> StatusClass:
    """Map a unit status string to its broad class.

    All seven current unit statuses (``passed``, ``failed``, ``crashed``,
    ``timeout``, ``empty``, ``crash_limited``, ``escalated``) map to a
    non-``"unknown"`` class.  Any other string returns ``"unknown"``.
    """
    if status in _FAILURE_STATUSES:
        return "failure"
    if status in _SKIPPED_STATUSES:
        return "skipped"
    if status == "passed":
        return "pass"
    return "unknown"


def load_results(path: Path) -> tuple[dict[str, str], dict[str, int]]:
    """Load a results JSON file; return ``(target→status map, summary dict)``.

    Verbatim port of ``_load_results`` from ``scripts/compare-results.py``.
    """
    data: dict[str, Any] = json.loads(path.read_text())
    units: list[dict[str, Any]] = data.get("units", [])
    target_map: dict[str, str] = {}
    for unit in units:
        target = str(unit.get("target", ""))
        status = str(unit.get("status", "unknown"))
        target_map[target] = status
    raw_summary: dict[str, Any] = data.get("summary", {})
    summary: dict[str, int] = {k: int(v) for k, v in raw_summary.items()}
    return target_map, summary


@dataclass(frozen=True)
class ResultsComparison:
    """Outcome of comparing a baseline results set to a current results set."""

    # Per-target crossings
    new_failures: list[str]
    """Targets whose status crossed into ``"failure"`` (or appeared as a failure)."""
    lost_coverage: list[str]
    """Previously-passing targets that are now absent."""
    new_passes: list[str]
    """Targets that crossed from ``"failure"`` to ``"pass"``."""
    new_skips: list[str]
    """Targets whose status crossed into ``"skipped"``."""
    unknown_statuses: list[tuple[str, str]]
    """``(target, status)`` pairs where a non-absent status is unrecognised."""
    status_changes: list[tuple[str, str, str]]
    """``(target, old_status, new_status)`` for other status changes."""

    # Full transition map (target → (base_status, curr_status)) for every target
    # whose status differed; used by ``render_text`` to show old→new detail lines.
    transitions: dict[str, tuple[str, str]]

    # Summary counters: metric → (base_value, curr_value)
    summary: dict[str, tuple[int, int]]
    """Keys: ``total``, ``passed``, ``failed``, ``crash``, ``skipped``."""

    # Verdict
    has_regressions: bool


def compare_results(
    base_map: dict[str, str],
    base_summary: dict[str, int],
    curr_map: dict[str, str],
    curr_summary: dict[str, int],
) -> ResultsComparison:
    """Compare two target→status maps and their summaries.

    The per-target crossing logic is ported verbatim from
    ``scripts/compare-results.py`` (lines 68-102), with the targeted changes
    described in the module docstring.
    """
    new_failures: list[str] = []
    new_passes: list[str] = []
    new_skips: list[str] = []
    lost_coverage: list[str] = []
    status_changes: list[tuple[str, str, str]] = []
    unknown_statuses: list[tuple[str, str]] = []
    transitions: dict[str, tuple[str, str]] = {}

    all_targets = sorted(set(base_map) | set(curr_map))
    for target in all_targets:
        base_status = base_map.get(target, "absent")
        curr_status = curr_map.get(target, "absent")

        if base_status == curr_status:
            # An unrecognized status identical in both files still must not slip through: the
            # equality short-circuit would otherwise hide it from the unknown-status report.
            if base_status != "absent" and status_class(base_status) == "unknown":
                unknown_statuses.append((target, base_status))
            continue

        transitions[target] = (base_status, curr_status)

        if base_status == "absent":
            if status_class(curr_status) == "unknown":
                unknown_statuses.append((target, curr_status))
            elif status_class(curr_status) == "failure":
                new_failures.append(target)
            else:
                status_changes.append((target, base_status, curr_status))
            continue

        if curr_status == "absent":
            if status_class(base_status) == "unknown":
                unknown_statuses.append((target, base_status))
            elif status_class(base_status) == "pass":
                # A target that was passing and is now gone is lost coverage — its
                # findings are no longer observed.  A previously skipped/failing
                # target going absent is only an informational status change.
                lost_coverage.append(target)
            else:
                status_changes.append((target, base_status, curr_status))
            continue

        base_cls = status_class(base_status)
        curr_cls = status_class(curr_status)

        # Record any unrecognised status and skip the standard crossing logic so
        # an unknown never silently falls through to a benign bucket.
        if base_cls == "unknown":
            unknown_statuses.append((target, base_status))
        if curr_cls == "unknown":
            unknown_statuses.append((target, curr_status))
        if base_cls == "unknown" or curr_cls == "unknown":
            continue

        if curr_cls == "failure" and base_cls != "failure":
            new_failures.append(target)
        elif base_cls == "failure" and curr_cls == "pass":
            new_passes.append(target)
        elif curr_cls == "skipped" and base_cls != "skipped":
            new_skips.append(target)
        else:
            status_changes.append((target, base_status, curr_status))

    # Summary deltas — identical to the script.
    # A file's unit status collapses to "failed" when ANY test in it fails, so
    # per-file crossings miss an INCREASE in the number of failing/crashing tests
    # inside already-red files.  Fold the summary-level count deltas into the
    # verdict so a 3→50 failure jump, or any new crash, is never reported as
    # "no regressions".  Crashes are weighed on their own: more crashes is a
    # regression even if total failures dropped.
    base_total = base_summary.get("total", len(base_map))
    curr_total = curr_summary.get("total", len(curr_map))
    base_pass = base_summary.get("passed", 0)
    curr_pass = curr_summary.get("passed", 0)
    base_fail = sum(base_summary.get(k, 0) for k in ("failed", "error", "crashed", "timeout"))
    curr_fail = sum(curr_summary.get(k, 0) for k in ("failed", "error", "crashed", "timeout"))
    base_crash = base_summary.get("crashed", 0) + base_summary.get("timeout", 0)
    curr_crash = curr_summary.get("crashed", 0) + curr_summary.get("timeout", 0)
    base_skip = base_summary.get("skipped", 0)
    curr_skip = curr_summary.get("skipped", 0)

    summary: dict[str, tuple[int, int]] = {
        "total": (base_total, curr_total),
        "passed": (base_pass, curr_pass),
        "failed": (base_fail, curr_fail),
        "crash": (base_crash, curr_crash),
        "skipped": (base_skip, curr_skip),
    }

    has_regressions = (
        bool(new_failures)
        or bool(lost_coverage)
        or (curr_fail > base_fail)
        or (curr_crash > base_crash)
        or bool(unknown_statuses)
    )

    return ResultsComparison(
        new_failures=new_failures,
        lost_coverage=lost_coverage,
        new_passes=new_passes,
        new_skips=new_skips,
        unknown_statuses=unknown_statuses,
        status_changes=status_changes,
        transitions=transitions,
        summary=summary,
        has_regressions=has_regressions,
    )


def render_text(
    cmp: ResultsComparison,
    *,
    baseline_name: str,
    current_name: str,
    verbose: bool,
) -> str:
    """Render a human-readable comparison report as a string.

    Reproduces the exact ``print(...)`` output of ``scripts/compare-results.py``
    (same headings, same ``+d`` deltas, same section order) with one addition:
    an ``UNKNOWN STATUSES (n)`` section when ``cmp.unknown_statuses`` is non-empty,
    and the corresponding reason appended to the ``RESULT:`` line.
    """
    buf = StringIO()

    base_total, curr_total = cmp.summary["total"]
    base_pass, curr_pass = cmp.summary["passed"]
    base_fail, curr_fail = cmp.summary["failed"]
    base_crash, curr_crash = cmp.summary["crash"]
    base_skip, curr_skip = cmp.summary["skipped"]

    fail_increase = curr_fail > base_fail
    crash_increase = curr_crash > base_crash

    def p(line: str = "") -> None:
        buf.write(line + "\n")

    p("=== Result Comparison ===")
    p(f"Baseline: {baseline_name}")
    p(f"Current:  {current_name}")
    p()
    p("Summary:")
    p(f"  Total tests: {base_total} -> {curr_total} ({curr_total - base_total:+d})")
    p(f"  Passed:      {base_pass} -> {curr_pass} ({curr_pass - base_pass:+d})")
    p(f"  Failed:      {base_fail} -> {curr_fail} ({curr_fail - base_fail:+d})")
    p(f"  Crashed+TO:  {base_crash} -> {curr_crash} ({curr_crash - base_crash:+d})")
    p(f"  Skipped:     {base_skip} -> {curr_skip} ({curr_skip - base_skip:+d})")

    if cmp.new_failures:
        p(f"\nNEW FAILURES ({len(cmp.new_failures)}):")
        for t in cmp.new_failures:
            base_s, curr_s = cmp.transitions.get(t, ("absent", "?"))
            p(f"  REGRESSION: {t}: {base_s} -> {curr_s}")

    if cmp.lost_coverage:
        p(f"\nLOST COVERAGE ({len(cmp.lost_coverage)} previously-exercised target(s) now absent):")
        for t in cmp.lost_coverage:
            base_s, _ = cmp.transitions.get(t, ("?", "absent"))
            p(f"  REGRESSION: {t}: {base_s} -> absent")

    if fail_increase:
        p(f"\nFAILURE COUNT INCREASED: {base_fail} -> {curr_fail} ({curr_fail - base_fail:+d})")

    if crash_increase:
        p(
            f"\nCRASH/TIMEOUT COUNT INCREASED: {base_crash} -> {curr_crash} "
            f"({curr_crash - base_crash:+d})"
        )

    if cmp.new_passes:
        p(f"\nNEW PASSES ({len(cmp.new_passes)}):")
        for t in cmp.new_passes:
            base_s, curr_s = cmp.transitions.get(t, ("?", "?"))
            p(f"  FIXED: {t}: {base_s} -> {curr_s}")

    if cmp.new_skips:
        p(f"\nNEW SKIPS ({len(cmp.new_skips)}):")
        for t in cmp.new_skips:
            base_s, curr_s = cmp.transitions.get(t, ("absent", "?"))
            p(f"  {t}: {base_s} -> {curr_s}")

    if verbose and cmp.status_changes:
        p(f"\nOTHER CHANGES ({len(cmp.status_changes)}):")
        for t, old, new in cmp.status_changes:
            p(f"  {t}: {old} -> {new}")

    if cmp.unknown_statuses:
        p(f"\nUNKNOWN STATUSES ({len(cmp.unknown_statuses)}):")
        for t, s in cmp.unknown_statuses:
            p(f"  {t}: {s}")

    if cmp.has_regressions:
        reasons: list[str] = []
        if cmp.new_failures:
            reasons.append(f"{len(cmp.new_failures)} new failure(s)")
        if cmp.lost_coverage:
            reasons.append(f"{len(cmp.lost_coverage)} lost-coverage target(s)")
        if fail_increase:
            reasons.append(f"failures +{curr_fail - base_fail}")
        if crash_increase:
            reasons.append(f"crashes/timeouts +{curr_crash - base_crash}")
        if cmp.unknown_statuses:
            reasons.append(f"{len(cmp.unknown_statuses)} unknown status(es)")
        p(f"\nRESULT: REGRESSIONS DETECTED ({', '.join(reasons)})")
    else:
        p("\nRESULT: NO REGRESSIONS")

    return buf.getvalue()
