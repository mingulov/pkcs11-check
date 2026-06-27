"""Render grouped findings into the compact-enriched provider markdown report.

Layout (severity-first, size-budgeted):

* header + counts line (``passed … · xfail … · fail … · crash …``)
* ``━━ 🔴 CRITICAL · fail (n) ━━`` then ``🟠 HIGH``, grouped within each by
  finding ``kind``
* a single collapsed ``🟡 deviations · xfail (n)`` section: one count line per
  xfail reason with a top example — never the full enumeration
* ``⚪`` one-liners for sanctioned-refusal compliance and unclassified

Even with thousands of findings the fail sections plus the collapsed xfail/
unclassified counts stay near one screen, because xfails and unclassified are
folded to one line per reason. No hashes anywhere.
"""

from __future__ import annotations

from typing import Any

_XFAIL_REASONS = ("not_operational", "nonspec_reject", "honest_deviation", "undeclared_capability")

# Severity sections in the order they are rendered, with marker + label.
_FAIL_SECTIONS: list[tuple[str, str]] = [
    ("CRITICAL", "🔴 CRITICAL"),
    ("HIGH", "🟠 HIGH"),
    ("MEDIUM", "🟡 MEDIUM"),
    ("LOW", "⚪ LOW"),
]


def _counts(groups: list[dict[str, Any]]) -> dict[str, int]:
    """Sum finding counts by logical bucket (fail/xfail/crash)."""
    out = {"fail": 0, "xfail": 0, "crash": 0}
    for g in groups:
        n = int(g.get("count", 0))
        if g.get("reason") == "crash":
            out["crash"] += n
        elif g.get("outcome") == "xfail":
            out["xfail"] += n
        elif g.get("outcome") == "fail":
            out["fail"] += n
    return out


def _counts_line(
    groups: list[dict[str, Any]], pass_count: int | None, crash_limited: int = 0
) -> str:
    c = _counts(groups)
    parts: list[str] = []
    if pass_count is not None:
        parts.append(f"passed {pass_count}")
    parts.append(f"xfail {c['xfail']}")
    parts.append(f"fail {c['fail']}")
    parts.append(f"crash {c['crash']}")
    if crash_limited:
        parts.append(f"crash_limited {crash_limited}")
    return " · ".join(parts)


def _kind_subheader(kind: str | None, reason: str) -> str:
    """``crypto · accepted_invalid`` — kind and reason keywords."""
    kindword = kind or "other"
    return f"{kindword} · {reason}"


def _finding_lines(g: dict[str, Any]) -> list[str]:
    """Two lines for one finding group: a count-prefixed headline + detail."""
    op = g.get("operation") or ""
    mech = g.get("mechanism") or ""
    summary = g.get("summary") or g.get("reason") or ""
    head = " ".join(p for p in (op, mech) if p)
    headline = f"[{g.get('count', 0)}] {head} — {summary}".replace("  ", " ").strip()

    detail_parts: list[str] = []
    expected = g.get("expected_ckr")
    if expected:
        detail_parts.append(f"want {', '.join(expected)}")
    actual = g.get("actual_ckr")
    if actual:
        detail_parts.append(f"got {actual}")
    spec_ref = g.get("spec_ref")
    if spec_ref:
        detail_parts.append(str(spec_ref))
    sources = g.get("sources") or []
    if sources:
        detail_parts.append(", ".join(sources))
    vector_ids = g.get("vector_ids") or []
    if vector_ids:
        detail_parts.append(" ".join(vector_ids))

    lines = [headline]
    if detail_parts:
        lines.append("  " + " · ".join(detail_parts))
    return lines


def _fail_section(severity: str, marker: str, groups: list[dict[str, Any]]) -> list[str]:
    """Render one severity section, grouping its members by kind/reason."""
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
    lines = [f"━━ {marker} · fail ({total}) ━━", ""]

    # group by (kind, reason); stable order by first appearance
    buckets: dict[tuple[str | None, str], list[dict[str, Any]]] = {}
    for g in members:
        buckets.setdefault((g.get("kind"), str(g.get("reason"))), []).append(g)

    for (kind, reason), grps in buckets.items():
        lines.append(f"### {_kind_subheader(kind, reason)}")
        for g in grps:
            lines.extend(_finding_lines(g))
        lines.append("")
    return lines


def _xfail_section(groups: list[dict[str, Any]]) -> list[str]:
    """Collapse ALL xfails to one count line per reason, with a top example."""
    xfails = [g for g in groups if g.get("outcome") == "xfail"]
    if not xfails:
        return []
    total = sum(int(g.get("count", 0)) for g in xfails)
    lines = [f"━━ 🟡 deviations · xfail ({total}) ━━", ""]

    for reason in _XFAIL_REASONS:
        members = [g for g in xfails if g.get("reason") == reason]
        if not members:
            continue
        n = sum(int(g.get("count", 0)) for g in members)
        top = max(members, key=lambda g: int(g.get("count", 0)))
        op = top.get("operation") or ""
        mech = top.get("mechanism") or ""
        example = " ".join(p for p in (op, mech) if p) or (top.get("summary") or "")
        lines.append(f"[{n}] {reason} — e.g. {example}".rstrip())
    lines.append("")
    return lines


def _oneliner_section(groups: list[dict[str, Any]]) -> list[str]:
    """``⚪`` one-liners: sanctioned-refusal compliance + unclassified bucket."""
    lines: list[str] = []
    sanctioned = [g for g in groups if g.get("reason") == "sanctioned_refusal"]
    if sanctioned:
        n = sum(int(g.get("count", 0)) for g in sanctioned)
        lines.append(f"⚪ compliance · {n} sanctioned refusals (CKR_OPERATION_NOT_VALIDATED)")
    unclassified = [g for g in groups if g.get("reason") == "unclassified"]
    if unclassified:
        n = sum(int(g.get("count", 0)) for g in unclassified)
        lines.append(f"⚪ {n} unclassified — un-migrated fail/xfail; see .jsonl")
    return lines


def render_provider(
    provider: str,
    groups: list[dict[str, Any]],
    pass_count: int | None = None,
    *,
    crash_limited: int = 0,
    incomplete: bool = False,
) -> str:
    """Render the compact-enriched markdown report for one provider.

    ``pass_count`` is optional; when ``None`` the ``passed`` token is omitted from
    the counts line.  ``crash_limited`` adds a ``crash_limited N`` token when > 0.
    ``incomplete`` emits an ``⚠ INCOMPLETE COVERAGE`` banner when ``True``.
    """
    out: list[str] = [
        f"# {provider} — conformance report",
        _counts_line(groups, pass_count, crash_limited),
        "",
    ]
    if incomplete:
        out.append(
            f"> ⚠ INCOMPLETE COVERAGE: {crash_limited} tests abandoned"
            " (per-file crash limit). Coverage is partial; re-run to probe them."
        )
        out.append("")

    # crash findings render as a CRITICAL-style block first (most actionable).
    crashes = [g for g in groups if g.get("reason") == "crash"]
    if crashes:
        total = sum(int(g.get("count", 0)) for g in crashes)
        out.append(f"━━ 🔴 CRASH · fail ({total}) ━━")
        out.append("")
        for g in crashes:
            target = g.get("test_file") or g.get("summary") or "?"
            out.append(f"[{g.get('count', 0)}] {target} — {g.get('summary', 'process crashed')}")
        out.append("")

    for severity, marker in _FAIL_SECTIONS:
        out.extend(_fail_section(severity, marker, groups))

    out.extend(_xfail_section(groups))
    out.extend(_oneliner_section(groups))

    # collapse trailing blank lines to exactly one terminal newline
    text = "\n".join(out).rstrip() + "\n"
    return text
