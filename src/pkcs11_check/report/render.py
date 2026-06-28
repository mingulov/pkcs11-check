"""Render grouped findings into the provider markdown report.

Layout (health-first, noise-reduced):

* header, then the health/coverage lines and an optional INCOMPLETE banner
* a "before you report" threat-model note
* a CRASH section (crashes summarized to the crashing C_* call, raw dump dropped)
* severity-ranked fail sections (``## CRITICAL`` -> ``## HIGH`` -> ...), grouped by
  ``kind/reason``; every line runs through the sanitizer (long hex truncated,
  want-lists capped), with the finding's routing/soft-token tags surfaced
* a capability-gap table (advertised-but-not-operational + not-supported counts)
* a collapsed ``## deviations (xfail)`` section: one line per reason with routing
* ``## appendix`` one-liners (sanctioned refusals, unclassified backlog)

Even with thousands of findings the report stays near one screen because xfails and
unclassified are folded to one line per reason and heavy detail lives in the .jsonl.
"""

from __future__ import annotations

from typing import Any

from pkcs11_check.report import health
from pkcs11_check.report.capability import render_capability_gaps
from pkcs11_check.report.sanitize import sanitize_line, summarize_crash, truncate_ckr_list

_XFAIL_REASONS = ("not_operational", "nonspec_reject", "honest_deviation", "undeclared_capability")

# Severity sections in render order (real markdown headings, not box-drawing).
_FAIL_SECTIONS: list[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# Routing values worth showing inline; the default fail routing carries no extra
# information beyond "this is a fail" and is omitted.
_HIDDEN_ROUTING = frozenset({"PROVIDER_REPORT"})

_THREAT_NOTE = (
    "A PKCS#11 module runs in-process, inside the calling application's trust boundary,"
    " and is generally built assuming the application calls the API as documented."
    " This suite deliberately sends hostile input (oversized lengths, malformed templates,"
    " invalid parameters) that a correct caller never sends; a finding from such a probe is,"
    " on its own, usually a hardening opportunity rather than an exploitable vulnerability"
    " in the in-process model. It becomes security-relevant when the module is exposed"
    " across a trust boundary (a remote/network PKCS#11 service, a proxy, or a multi-tenant"
    " host), a different threat model. Treat each finding as a lead to assess against your"
    " deployment - not as a CVE, and not as something to forward to the module's authors"
    " without that assessment."
)


def _kind_subheader(kind: str | None, reason: str) -> str:
    """``crypto · accepted_invalid`` - kind and reason keywords."""
    return f"{kind or 'other'} · {reason}"


def _finding_lines(g: dict[str, Any]) -> list[str]:
    """Two lines for one finding group: a count-prefixed headline + detail."""
    op = g.get("operation") or ""
    mech = g.get("mechanism") or ""
    summary = sanitize_line(str(g.get("summary") or g.get("reason") or ""))
    head = " ".join(p for p in (op, mech) if p)
    headline = f"[{g.get('count', 0)}] {head} - {summary}".replace("  ", " ").strip()

    detail: list[str] = []
    expected = g.get("expected_ckr")
    if expected:
        detail.append(f"want {truncate_ckr_list([str(c) for c in expected])}")
    actual = g.get("actual_ckr")
    if actual:
        detail.append(f"got {actual}")
    spec_ref = g.get("spec_ref")
    if spec_ref:
        detail.append(str(spec_ref))
    routing = g.get("routing")
    if routing and routing not in _HIDDEN_ROUTING:
        detail.append(f"-> {routing}")
    if g.get("soft_token_caveat"):
        detail.append("(soft-token caveat)")
    nodeids = g.get("nodeids") or []
    if nodeids:
        detail.append(str(nodeids[0]))

    lines = [headline]
    if detail:
        lines.append("  " + " · ".join(detail))
    return lines


def _crash_section(groups: list[dict[str, Any]]) -> list[str]:
    """Render crashes first: descriptor + crashing C_* call, raw dump dropped."""
    crashes = [g for g in groups if g.get("reason") == "crash"]
    if not crashes:
        return []
    total = sum(int(g.get("count", 0)) for g in crashes)
    out = [f"## CRASH ({total})", ""]
    for g in crashes:
        target = g.get("test_file") or g.get("summary") or "?"
        summ = summarize_crash(str(g.get("summary", "process crashed")))
        out.append(f"[{g.get('count', 0)}] {target} - {summ}")
    out.append("")
    return out


def _fail_section(severity: str, groups: list[dict[str, Any]]) -> list[str]:
    """Render one severity section, grouping its members by kind/reason (count desc)."""
    members = [
        g
        for g in groups
        if g.get("outcome") == "fail"
        and g.get("severity") == severity
        and g.get("reason") not in ("unclassified", "crash")
    ]
    if not members:
        return []
    total = sum(int(g.get("count", 0)) for g in members)
    out = [f"## {severity} - fail ({total})", ""]

    buckets: dict[tuple[str | None, str], list[dict[str, Any]]] = {}
    for g in members:
        buckets.setdefault((g.get("kind"), str(g.get("reason"))), []).append(g)

    for (kind, reason), grps in buckets.items():
        out.append(f"### {_kind_subheader(kind, reason)}")
        for g in sorted(grps, key=lambda x: -int(x.get("count", 0))):
            out.extend(_finding_lines(g))
        out.append("")
    return out


def _xfail_section(groups: list[dict[str, Any]]) -> list[str]:
    """Collapse ALL xfails to one count line per reason, with routing + a top example."""
    xfails = [g for g in groups if g.get("outcome") == "xfail"]
    if not xfails:
        return []
    total = sum(int(g.get("count", 0)) for g in xfails)
    out = [f"## deviations (xfail) ({total})", ""]
    for reason in _XFAIL_REASONS:
        members = [g for g in xfails if g.get("reason") == reason]
        if not members:
            continue
        n = sum(int(g.get("count", 0)) for g in members)
        top = max(members, key=lambda g: int(g.get("count", 0)))
        routing = str(top.get("routing") or "")
        op = top.get("operation") or ""
        mech = top.get("mechanism") or ""
        example = " ".join(p for p in (op, mech) if p) or sanitize_line(
            str(top.get("summary") or "")
        )
        suffix = f" -> {routing}" if routing else ""
        out.append(f"[{n}] {reason}{suffix} - e.g. {example}".rstrip())
    out.append("")
    return out


def _appendix(groups: list[dict[str, Any]]) -> list[str]:
    """``## appendix``: sanctioned-refusal compliance + unclassified backlog."""
    lines: list[str] = []
    sanctioned = sum(
        int(g.get("count", 0)) for g in groups if g.get("reason") == "sanctioned_refusal"
    )
    unclassified = sum(int(g.get("count", 0)) for g in groups if g.get("reason") == "unclassified")
    if sanctioned:
        lines.append(
            f"- compliance: {sanctioned} sanctioned refusals (CKR_OPERATION_NOT_VALIDATED)"
        )
    if unclassified:
        lines.append(
            f"- unclassified backlog: {unclassified} un-migrated fail/xfail (framework debt)"
        )
    lines.append("- full detail (raw stdout/stderr, full traces, full hex): see <provider>.jsonl")
    return ["## appendix", "", *lines]


def render_provider(
    provider: str,
    groups: list[dict[str, Any]],
    *,
    summary: dict[str, Any] | None = None,
    coverage: dict[str, Any] | None = None,
    units: list[dict[str, Any]] | None = None,
    quality: dict[str, Any] | None = None,
) -> str:
    """Render the noise-reduced markdown report for one provider.

    ``summary``/``coverage`` are the results.json blocks; ``units`` the results.json
    unit list (for the incomplete banner); ``quality`` the quality.json payload (for
    the not-supported skip counts). All are optional so callers can render from groups
    alone.
    """
    summary = summary or {}
    out: list[str] = [f"# {provider} - conformance report", ""]
    out.extend(health.health_lines(summary, coverage, groups))
    out.append("")

    banner = health.incomplete_banner(summary, units or [])
    if banner:
        out.append(f"> {banner}")
        out.append("")

    out.append("## before you report")
    out.append("")
    out.append(_THREAT_NOTE)
    out.append("")

    out.extend(_crash_section(groups))
    for severity in _FAIL_SECTIONS:
        out.extend(_fail_section(severity, groups))

    mech_cov = (coverage or {}).get("mechanism_coverage")
    fsc = (quality or {}).get("framework_skip_candidates")
    out.append(render_capability_gaps(mech_cov, fsc).rstrip())
    out.append("")

    out.extend(_xfail_section(groups))
    out.extend(_appendix(groups))

    return "\n".join(out).rstrip() + "\n"
