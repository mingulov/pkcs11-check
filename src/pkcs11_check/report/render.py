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

import re
from collections import Counter
from typing import Any

from pkcs11_check.report import health
from pkcs11_check.report.capability import render_capability_gaps
from pkcs11_check.report.sanitize import sanitize_line, summarize_crash, truncate_ckr_list

# Parse a coverage.invoked_detail entry: ``CKM_X[k1=v1,k2=v2]`` -> mechanism, params.
_INVOKED_DETAIL_RE = re.compile(r"^(CKM_[A-Z0-9_]+)\[(.+)\]$")

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

_AUTOMATION_NOTE = (
    "This report is produced by an automated suite and is not hand-verified: it can both"
    " MISS real issues (a probe that does not cover them, or a finding mis-bucketed as a"
    " benign deviation - false negatives) and OVER-REPORT (false positives, or harness"
    " artifacts that are not module defects). Also, a large fail/xfail count is usually one"
    " underlying behavior repeated across many test vectors, not that many distinct defects"
    " - read the per-finding count, the `by param` breakdown, and the reproducer before"
    " concluding. Treat every line as a lead to verify against the module's behavior and the"
    " PKCS#11 spec; investigate deeper before acting on or forwarding it."
)


def _provenance_line(provenance: dict[str, Any] | None) -> str:
    """One compact 'tested: <provider> | by pkcs11-check <ver> | data: ...' line, or ''."""
    if not provenance:
        return ""
    parts: list[str] = []
    prov = provenance.get("provider")
    if isinstance(prov, dict):
        ref = prov.get("ref") or ""
        commit = (prov.get("commit") or "")[:8]
        pin = ""
        if prov.get("matches_manifest_pin") is True:
            pin = " (matches pin)"
        elif prov.get("matches_manifest_pin") is False:
            pin = " (NOT pinned source)"
        head = f"{prov.get('name', '?')} {ref}@{commit}".replace(" @", " ").strip()
        parts.append(f"tested: {head}{pin}")
    fw = provenance.get("framework")
    if isinstance(fw, dict) and fw.get("version"):
        parts.append(f"by pkcs11-check {fw['version']}")
    data = provenance.get("test_data")
    if isinstance(data, list) and data:
        handles = ", ".join(
            f"{d.get('name')}@{(d.get('commit') or '')[:8]}" for d in data if d.get("name")
        )
        if handles:
            parts.append(f"data: {handles}")
    return " | ".join(parts)


def _top_params(param_breakdown: dict[str, int], top: int = 5) -> str:
    """Format the highest-count param combos, e.g. ``curve=secp256k1 (1747), ...``."""
    items = sorted(param_breakdown.items(), key=lambda kv: (-kv[1], kv[0]))[:top]
    return ", ".join(f"{k} ({n})" for k, n in items)


def _kind_subheader(kind: str | None, reason: str) -> str:
    """``crypto · accepted_invalid`` - kind and reason keywords."""
    return f"{kind or 'other'} · {reason}"


def _reproducer_handle(g: dict[str, Any], max_ids: int = 3) -> str:
    """Format the reproducer handle (vector file + a few case ids) for a finding.

    ``sources``/``vector_ids`` are computed and capped by the extractor; surfacing
    them gives the reader a directly-runnable handle instead of leaving it in the
    .jsonl. Returns ``""`` when neither is present.
    """
    sources = [str(s) for s in (g.get("sources") or [])][:2]
    vector_ids = [str(v) for v in (g.get("vector_ids") or [])][:max_ids]
    if not sources and not vector_ids:
        return ""
    parts = ", ".join(sources)
    if vector_ids:
        ids = " ".join(vector_ids)
        parts = f"{parts} [{ids}]" if parts else ids
    return f"repro {parts}"


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
    repro = _reproducer_handle(g)
    if repro:
        detail.append(repro)
    param_breakdown = g.get("param_breakdown") or {}
    if param_breakdown:
        detail.append(f"params {_top_params(param_breakdown)}")

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
        target = str(g.get("test_file") or g.get("summary") or "?")
        summ = summarize_crash(str(g.get("summary", "process crashed")))
        # runner-side crashes summarize to "<target>: process crashed" - drop the
        # leading target so it is not printed twice.
        if summ.startswith(target):
            summ = summ[len(target) :].lstrip(": ").strip() or "process crashed"
        detail_raw = g.get("detail")
        detail = detail_raw if isinstance(detail_raw, dict) else {}
        tag = detail.get("signal") or detail.get("mode")
        if tag and str(tag) not in summ:
            summ = f"{summ} ({tag})"
        out.append(f"[{g.get('count', 0)}] {target} - {summ}")
    out.append("")
    return out


def _render_fail_buckets(members: list[dict[str, Any]]) -> list[str]:
    """Group fail members by kind/reason (count desc) into ``###`` sub-sections."""
    buckets: dict[tuple[str | None, str], list[dict[str, Any]]] = {}
    for g in members:
        buckets.setdefault((g.get("kind"), str(g.get("reason"))), []).append(g)
    out: list[str] = []
    for (kind, reason), grps in buckets.items():
        out.append(f"### {_kind_subheader(kind, reason)}")
        for g in sorted(grps, key=lambda x: -int(x.get("count", 0))):
            out.extend(_finding_lines(g))
        out.append("")
    return out


def _is_scored_fail(g: dict[str, Any]) -> bool:
    """A fail that counts toward the header total (excludes crash + unclassified)."""
    return g.get("outcome") == "fail" and g.get("reason") not in ("unclassified", "crash")


def _fail_section(severity: str, groups: list[dict[str, Any]]) -> list[str]:
    """Render one severity section, grouping its members by kind/reason (count desc)."""
    members = [g for g in groups if _is_scored_fail(g) and g.get("severity") == severity]
    if not members:
        return []
    total = sum(int(g.get("count", 0)) for g in members)
    return [f"## {severity} - fail ({total})", "", *_render_fail_buckets(members)]


def _uncategorized_fail_section(groups: list[dict[str, Any]]) -> list[str]:
    """Catch-all so a scored fail is NEVER silently dropped.

    A fail whose severity is outside the four known sections is still counted by the
    header (``health.outcome_counts``); without this section the header total would
    exceed the rendered findings - a hidden finding. Render any such straggler under
    an explicit ``## other severity`` heading.
    """
    members = [g for g in groups if _is_scored_fail(g) and g.get("severity") not in _FAIL_SECTIONS]
    if not members:
        return []
    total = sum(int(g.get("count", 0)) for g in members)
    return [f"## other severity - fail ({total})", "", *_render_fail_buckets(members)]


def _xfail_section(groups: list[dict[str, Any]]) -> list[str]:
    """Collapse ALL xfails to one count line per reason, with routing + a top example."""
    xfails = [g for g in groups if g.get("outcome") == "xfail"]
    if not xfails:
        return []
    total = sum(int(g.get("count", 0)) for g in xfails)
    out = [f"## deviations (xfail) ({total})", ""]
    # Render the known reasons in a stable order, then any leftover reason, so the per-reason
    # lines always sum to the heading total (a new xfail reason can never go uncounted).
    present = {str(g.get("reason") or "") for g in xfails}
    leftover = sorted(present - set(_XFAIL_REASONS))
    for reason in (*_XFAIL_REASONS, *leftover):
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
        line = f"[{n}] {reason}{suffix} - e.g. {example}".rstrip()
        agg: Counter[str] = Counter()
        for member in members:
            for key, value in (member.get("param_breakdown") or {}).items():
                agg[key] += int(value)
        if agg:
            line += f" | by param: {_top_params(dict(agg))}"
        out.append(line)
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


def _invoked_params_section(coverage: dict[str, Any] | None) -> list[str]:
    """Surface the per-mechanism param variants the suite actually invoked.

    ``coverage.invoked_detail`` carries entries like ``CKM_AES_GCM[tagBits=0]`` /
    ``CKM_AES_CTR[counterBits=129]`` - evidence of which edge parameters were exercised,
    computed but never rendered. Bare mechanisms (no ``[params]``) are omitted; the list
    is capped with a ``(+N)`` overflow marker.
    """
    mc = (coverage or {}).get("mechanism_coverage") or {}
    detail = mc.get("invoked_detail") or []
    # group by mechanism, collapsing the value set per param key, so a 5x5 OAEP
    # hashAlg/mgf matrix is one line rather than 25, while edge values stay visible.
    grouped: dict[str, dict[str, set[str]]] = {}
    total = 0
    for entry in detail:
        match = _INVOKED_DETAIL_RE.match(str(entry))
        if not match:
            continue
        total += 1
        mech, params = match.group(1), match.group(2)
        keys = grouped.setdefault(mech, {})
        for kv in params.split(","):
            key, _, value = kv.partition("=")
            keys.setdefault(key.strip(), set()).add(value.strip())
    if not grouped:
        return []

    def _sort_key(value: str) -> tuple[int, int, str]:
        # numeric values first, in numeric order (tagBits 8 before 128), then strings
        return (0, int(value), "") if value.isdigit() else (1, 0, value)

    out = [f"## mechanism params exercised ({total})", ""]
    for mech in sorted(grouped):
        body = "; ".join(
            f"{key}={','.join(sorted(vals, key=_sort_key))}"
            for key, vals in sorted(grouped[mech].items())
        )
        out.append(f"- {mech}[{body}]")
    out.append("")
    return out


def _in_range_contradiction_line(groups: list[dict[str, Any]]) -> str:
    """Surface the T2 advertised-IN_RANGE-then-refused contradiction candidates.

    These are not_operational records the capability gate proved advertised in-range,
    that then cleanly refused (detail.capability_verdict == "IN_RANGE") - the subset
    worth investigating, distinct from honest capability gaps.
    """
    in_range = [
        g
        for g in groups
        if isinstance(g.get("detail"), dict) and g["detail"].get("capability_verdict") == "IN_RANGE"
    ]
    if not in_range:
        return ""
    total = sum(int(g.get("count", 0)) for g in in_range)
    mechs = sorted({str(g.get("mechanism")) for g in in_range if g.get("mechanism")})
    examples = ", ".join(mechs[:6]) or "see .jsonl"
    return f"- advertised IN-RANGE then refused (contradiction candidates): {total}: {examples}"


def render_provider(
    provider: str,
    groups: list[dict[str, Any]],
    *,
    summary: dict[str, Any] | None = None,
    coverage: dict[str, Any] | None = None,
    units: list[dict[str, Any]] | None = None,
    quality: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
) -> str:
    """Render the noise-reduced markdown report for one provider.

    ``summary``/``coverage`` are the results.json blocks; ``units`` the results.json
    unit list (for the incomplete banner); ``quality`` the quality.json payload (for
    the not-supported skip counts); ``provenance`` the results.json provenance block
    (for the compact header attribution line). All are optional so callers can render
    from groups alone.
    """
    summary = summary or {}
    out: list[str] = [f"# {provider} - conformance report", ""]
    out.extend(health.health_lines(summary, coverage, groups))
    out.append("")

    banner = health.incomplete_banner(summary, units or [])
    if banner:
        out.append(f"> {banner}")
        out.append("")

    dq_raw = (quality or {}).get("data_quality_warnings")
    dq_warnings = dq_raw if isinstance(dq_raw, list) else []
    for warning in dq_warnings:
        out.append(f"> data quality caveat: {warning}")
    if dq_warnings:
        out.append("")

    prov_line = _provenance_line(provenance)
    if prov_line:
        out.append(prov_line)
        out.append("")

    out.append("## before you report")
    out.append("")
    out.append(_THREAT_NOTE)
    out.append("")
    out.append(_AUTOMATION_NOTE)
    out.append("")

    out.extend(_crash_section(groups))
    for severity in _FAIL_SECTIONS:
        out.extend(_fail_section(severity, groups))
    out.extend(_uncategorized_fail_section(groups))

    mech_cov = (coverage or {}).get("mechanism_coverage")
    fsc = (quality or {}).get("framework_skip_candidates")
    mech_findings = (quality or {}).get("mechanism_findings")
    capability = render_capability_gaps(mech_cov, fsc, mech_findings).rstrip()
    contradiction = _in_range_contradiction_line(groups)
    if contradiction:
        capability = f"{capability}\n{contradiction}"
    out.append(capability)
    out.append("")

    out.extend(_invoked_params_section(coverage))
    out.extend(_xfail_section(groups))
    out.extend(_appendix(groups))

    return "\n".join(out).rstrip() + "\n"
