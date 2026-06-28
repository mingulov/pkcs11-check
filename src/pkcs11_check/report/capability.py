# pkcs11_check/report/capability.py
"""Per-provider capability audit: in-range advertised-but-not-operational findings.

The actionable signal is the contradiction candidates -- not_operational records
whose detail.capability_verdict == "IN_RANGE" (the module advertised the exact
size/mechanism then refused it). The genuine-absence denominator (mechanisms not
advertised at all) is the coverage meta-check's job and is referenced, not recomputed.
"""

from __future__ import annotations

from typing import Any


def capability_audit(groups: list[dict[str, Any]]) -> dict[str, int]:
    """Summarise not_operational records and the in-range contradiction subset."""
    total = 0
    claimed = 0
    for g in groups:
        if g.get("reason") != "not_operational":
            continue
        n = int(g.get("count", 0))
        total += n
        detail = g.get("detail") or {}
        if isinstance(detail, dict) and detail.get("capability_verdict") == "IN_RANGE":
            claimed += n
    return {"not_operational_total": total, "claimed_refused": claimed}


def render_capability_section(audit: dict[str, int]) -> str:
    """Render the capability-audit markdown section for a provider page."""
    total = audit["not_operational_total"]
    claimed = audit["claimed_refused"]
    lines = [
        "## capability audit",
        "",
        f"- advertised-but-not-operational (xfail) records: **{total}**",
        f"- of which **claimed→refused** (in-range, contradiction candidates to investigate): "
        f"**{claimed}**",
        "",
        "_Genuine-absence (mechanism not advertised) counts come from the coverage "
        "meta-check, not this summary._",
    ]
    return "\n".join(lines) + "\n"


# --- capability-gap table (mechanism axis) ----------------------------------
# Replaces the always-zero IN_RANGE "claimed_refused" scalar with a real view of
# which advertised mechanisms do not work, plus what the module does not support
# at all (from quality.json framework_skip_candidates). Curve/key-size axis is
# added later once tests emit a structured `params` attribute.


def advertised_not_operational(mechanism_coverage: dict[str, Any] | None) -> dict[str, list[str]]:
    """Partition advertised mechanisms that do not cleanly work, via set algebra.

    Returns sorted name lists for: ``rejected_cleanly`` (advertised yet a canonical
    op was cleanly refused), ``crashed``, ``timeout``, and ``limbo`` (advertised but
    never cleanly accepted nor rejected and did not crash/timeout).
    """
    mc = mechanism_coverage or {}
    advertised = set(mc.get("advertised_names", []))
    accepted = set(mc.get("accepted_names", []))
    rejected = set(mc.get("rejected_cleanly_names", []))
    crashed = set(mc.get("crashed_names", []))
    timeout = set(mc.get("timeout_names", []))
    return {
        # rejected AND never accepted: a real "advertised but no canonical op worked"
        # gap. A mechanism that also appears in accepted_names worked in some scenario
        # and was merely refused in another - not a gap, and listing it (e.g.
        # CKM_RSA_PKCS) reads alarmingly as "the mechanism is broken".
        "rejected_cleanly": sorted(advertised & rejected - accepted),
        "crashed": sorted(advertised & crashed),
        "timeout": sorted(advertised & timeout),
        "limbo": sorted(advertised - accepted - rejected - crashed - timeout),
    }


def never_invoked_advertised(mechanism_findings: list[dict[str, Any]] | None) -> list[str]:
    """Advertised mechanisms the run never invoked - a coverage gap on OUR side, not a
    module defect. From quality.json ``mechanism_findings`` (names already CKM_ form)."""
    out = set()
    for mf in mechanism_findings or []:
        if isinstance(mf, dict) and mf.get("advertised") and not mf.get("invoked"):
            name = mf.get("mechanism")
            if name:
                out.add(str(name))
    return sorted(out)


def skip_reasons(
    framework_skip_candidates: list[dict[str, Any]] | None, limit: int = 10
) -> list[dict[str, Any]]:
    """Top ``missing_capability`` skip reasons by vector count (descending, stable)."""
    cands = [
        c for c in (framework_skip_candidates or []) if c.get("category") == "missing_capability"
    ]
    cands.sort(key=lambda c: (-int(c.get("count", 0) or 0), str(c.get("reason", ""))))
    return cands[:limit]


def _capped(names: list[str], cap: int = 12) -> str:
    """Join names, truncating to ``cap`` with a ``(+N)`` overflow marker."""
    if len(names) <= cap:
        return ", ".join(names)
    return ", ".join(names[:cap]) + f" (+{len(names) - cap})"


def render_capability_gaps(
    mechanism_coverage: dict[str, Any] | None,
    framework_skip_candidates: list[dict[str, Any]] | None,
    mechanism_findings: list[dict[str, Any]] | None = None,
) -> str:
    """Render the capability-gap markdown section from coverage + skip candidates.

    When ``mechanism_findings`` is given, the "no canonical accept/reject" (limbo) row
    is split into the subset the run NEVER invoked (a coverage gap on our side, not a
    module defect) versus those invoked-but-inconclusive, so the report does not
    mis-blame the module for mechanisms pkcs11-check simply never exercised.
    """
    gaps = advertised_not_operational(mechanism_coverage)
    lines = ["## capability gaps", ""]
    rows = [
        ("advertised but rejected a canonical op", gaps["rejected_cleanly"]),
        ("advertised but CRASHED on probe", gaps["crashed"]),
        ("advertised but TIMED OUT on probe", gaps["timeout"]),
    ]
    never = set(never_invoked_advertised(mechanism_findings))
    if never:
        limbo_never = [m for m in gaps["limbo"] if m in never]
        limbo_other = [m for m in gaps["limbo"] if m not in never]
        rows.append(
            (
                "advertised but never invoked this run (coverage gap, not a module defect)",
                limbo_never,
            )
        )
        rows.append(("advertised, invoked but no canonical accept/reject", limbo_other))
    else:
        rows.append(("advertised, no canonical accept/reject observed", gaps["limbo"]))
    any_row = False
    for label, names in rows:
        if names:
            any_row = True
            lines.append(f"- {label} ({len(names)}): {_capped(names)}")
    skips = skip_reasons(framework_skip_candidates)
    if skips:
        any_row = True
        lines.append("")
        lines.append("not supported by the module (vectors skipped):")
        for s in skips:
            lines.append(f"- {s.get('reason')} (x{int(s.get('count', 0) or 0)})")
    if not any_row:
        lines.append("- no advertised-capability gaps observed")
    return "\n".join(lines) + "\n"
