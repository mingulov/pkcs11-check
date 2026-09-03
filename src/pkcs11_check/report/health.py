"""Header health and coverage summary lines for a provider report.

Pure functions over the results.json ``summary``/``coverage`` blocks, the
``units`` list, and the enriched finding groups. The renderer composes these into
the report header so the reader sees run quality (pass rate, severity of fails,
crashes, abandoned coverage) and mechanism coverage at a glance, instead of a bare
``passed N`` count. Nothing here reads raw logs or has side effects.
"""

from __future__ import annotations

import os
from typing import Any

from pkcs11_check.classification import HARNESS_REASONS

_FAIL_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_SEP = " · "  # middle dot, matching the existing report separator


def fail_severity_counts(groups: list[dict[str, Any]]) -> dict[str, int]:
    """Sum ``count`` per severity for provider-attributed fails.

    ``unclassified`` is a provider-fail subset and remains separately counted as
    migration backlog; only crashes and harness errors stay outside these totals.
    """
    out = {sev: 0 for sev in _FAIL_SEVERITIES}
    for g in groups:
        if g.get("outcome") != "fail":
            continue
        if g.get("reason") == "crash" or g.get("reason") in HARNESS_REASONS:
            continue
        sev = str(g.get("severity") or "")
        if sev in out:
            out[sev] += int(g.get("count", 0))
    return out


def outcome_counts(groups: list[dict[str, Any]]) -> dict[str, int]:
    """Partition finding ``count`` into fail / crash / xfail / unclassified buckets.

    ``unclassified`` is retained as a separate migration-backlog subset while also
    contributing to the provider fail total. Crashes and harness errors stay separate.
    """
    out = {"fail": 0, "crash": 0, "xfail": 0, "unclassified": 0, "harness_error": 0}
    for g in groups:
        n = int(g.get("count", 0))
        reason = g.get("reason")
        if reason in HARNESS_REASONS:
            # pkcs11-check's own defect: never counted against the module under test.
            out["harness_error"] += n
        elif reason == "crash":
            out["crash"] += n
        elif g.get("outcome") == "xfail":
            out["xfail"] += n
        elif g.get("outcome") == "fail":
            out["fail"] += n
        if reason == "unclassified":
            out["unclassified"] += n
    return out


def coverage_funnel(coverage: dict[str, Any] | None) -> str | None:
    """Render a one-line mechanism + function coverage funnel, or None if absent."""
    cov = coverage or {}
    mech = cov.get("mechanism_coverage") or {}
    func = cov.get("function_coverage") or {}
    parts: list[str] = []
    if mech:
        # The funnel is "of the advertised mechanisms": each stage is intersected with
        # advertised so it stays a true subset chain. invoked_names can include
        # mechanisms the harness probed but the module never advertised (so the raw
        # invoked count exceeded advertised); those extras are surfaced separately
        # rather than folded into the funnel.
        adv = set(mech.get("advertised_names", []))
        advertised = len(adv)
        inv_names = mech.get("invoked_names")
        if inv_names:
            inv_set = set(inv_names)
            invoked = len(adv & inv_set)
            extra = len(inv_set - adv)
        else:
            invoked = int(mech.get("invoked", 0))
            extra = 0
        accepted = len(adv & set(mech.get("accepted_names", [])))
        rejected = len(adv & set(mech.get("rejected_cleanly_names", [])))
        line = (
            f"mechanisms advertised {advertised} -> invoked {invoked} -> "
            f"accepted {accepted} (rejected {rejected})"
        )
        if extra:
            line += f"; +{extra} invoked not advertised"
        parts.append(line)
    if func:
        called = int(func.get("called", len(func.get("called_names", []))))
        available = int(func.get("available", 0))
        parts.append(f"functions {called}/{available}")
    return _SEP.join(parts) if parts else None


def health_lines(
    summary: dict[str, Any], coverage: dict[str, Any] | None, groups: list[dict[str, Any]]
) -> list[str]:
    """Build the header health line(s): a counts/severity line plus a coverage funnel."""
    passed = int(summary.get("passed", 0))
    total = int(summary.get("total", 0))
    pct = f"{100 * passed / total:.0f}%" if total else "0%"
    counts = outcome_counts(groups)
    sev = fail_severity_counts(groups)

    parts = [
        f"passed {passed}/{total} ({pct})",
        f"fail {counts['fail']} (CRITICAL {sev['CRITICAL']}{_SEP}HIGH {sev['HIGH']})",
        f"crash {counts['crash']}",
        f"xfail {counts['xfail']}",
    ]
    if counts["unclassified"]:
        parts.append(f"unclassified {counts['unclassified']} (migration backlog)")
    error = int(summary.get("error", 0))
    if error:
        parts.append(f"error {error}")

    lines = [_SEP.join(parts)]
    funnel = coverage_funnel(coverage)
    if funnel:
        lines.append(funnel)
    return lines


def incomplete_banner(summary: dict[str, Any], units: list[dict[str, Any]]) -> str | None:
    """Return an INCOMPLETE-COVERAGE banner naming the abandoned units, or None."""
    if not summary.get("incomplete"):
        return None

    abandoned: list[str] = []
    for unit in units:
        counts = unit.get("counts") or {}
        crash_limited = int(counts.get("crash_limited", 0) or 0)
        timed_out = unit.get("status") == "timeout" or int(counts.get("timeout", 0) or 0) > 0
        if crash_limited <= 0 and not timed_out:
            continue
        name = os.path.basename(str(unit.get("target", ""))) or "?"
        causes: list[str] = []
        if crash_limited:
            causes.append(f"{crash_limited} crash-limited")
        if timed_out:
            causes.append("timed out")
        duration = float(unit.get("duration_s", 0) or 0)
        abandoned.append(f"{name} ({', '.join(causes)}, {duration:.0f}s)")

    crash_limited_total = int(summary.get("crash_limited", 0) or 0)
    timeout_total = int(summary.get("timeout", 0) or 0)
    status_only_timed_out_units = sum(
        1
        for unit in units
        if unit.get("status") == "timeout"
        and int((unit.get("counts") or {}).get("timeout", 0) or 0) == 0
    )
    summary_causes: list[str] = []
    if crash_limited_total:
        summary_causes.append(f"{crash_limited_total} tests abandoned (crash limit)")
    if timeout_total:
        summary_causes.append(f"{timeout_total} timed out")
    if status_only_timed_out_units:
        noun = "unit" if status_only_timed_out_units == 1 else "units"
        summary_causes.append(f"{status_only_timed_out_units} {noun} timed out")
    cause = " + ".join(summary_causes) or "unit execution abandoned"
    detail = "; ".join(abandoned) if abandoned else "see results.json units"
    return (
        f"INCOMPLETE COVERAGE: {cause}. Affected: {detail}. "
        "Coverage is partial; re-run to probe them."
    )
