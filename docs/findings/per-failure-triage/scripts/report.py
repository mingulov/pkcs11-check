#!/usr/bin/env python3
"""Phase 7+8: Render per-provider and cross-provider reports from verdicts.jsonl.

Outputs (under docs/findings/per-failure-triage/reports/):
  _index.md            — executive summary across all 7 providers
  _universal.md        — cross-provider correlation (universal patterns)
  <provider>.md        — one per in-scope provider (7 files)

Effective-view rule: a verdict record is "effective" if no other record has
`supersedes` pointing at its signature. Superseded records are dropped from
reporting. UNKNOWN records are surfaced in a separate "not yet classified"
section per provider, but not listed as findings.

Reads verdicts.jsonl; no network; no fresh classification. Idempotent.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

VERDICTS = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/verdicts.jsonl")
OUT = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/reports")

PROVIDERS = [
    "wolfpkcs11-master",
    "opencryptoki-master",
    "corepkcs11-main",
    "kryoptic-main",
    "nss-main",
    "softhsm2-main",
    "tpm2",
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
CATEGORY_ORDER = {
    "PROVIDER_BUG": 0,
    "UPSTREAM_BUG": 1,
    "HARNESS_BUG": 2,
    "SOFT_TOKEN_CAVEAT": 3,
    "SPEC_AMBIGUITY": 4,
    "KNOWN_ISSUE": 5,
    "UNKNOWN": 6,
    "FALSE_POSITIVE": 7,
}

# Routing icons for quick scan
ROUTING_ICON = {
    "USER_ESCALATION": "🚨",
    "PROVIDER_REPORT": "📨",
    "HARNESS_FIX": "🔧",
    "DOCS_ONLY": "📚",
    "MANUAL_REVIEW": "🔍",
}


@dataclass
class Verdict:
    provider: str
    signature: str
    outcome: str
    message: str
    test_file: str
    direction: str
    category: str
    severity: str
    evidence: str
    routing: str
    group_id: str
    group_size: int
    example_nodeid: str
    analyzed_at: str
    analyzer: str
    raw: dict


def load_effective() -> list[Verdict]:
    raw = [json.loads(l) for l in VERDICTS.read_text().splitlines() if l.strip()]
    superseded = {v["supersedes"] for v in raw if "supersedes" in v}
    out = []
    for v in raw:
        if v["signature"] in superseded:
            continue
        out.append(
            Verdict(
                provider=v["provider"],
                signature=v["signature"],
                outcome=v.get("outcome", ""),
                message=v.get("message", ""),
                test_file=v.get("test_file", ""),
                direction=v.get("direction", ""),
                category=v.get("category", "UNKNOWN"),
                severity=v.get("severity", "INFO"),
                evidence=v.get("evidence", ""),
                routing=v.get("routing", ""),
                group_id=v.get("group_id", ""),
                group_size=v.get("group_size", 1),
                example_nodeid=v.get("example_nodeid", ""),
                analyzed_at=v.get("analyzed_at", ""),
                analyzer=v.get("analyzer", ""),
                raw=v,
            )
        )
    return out


def slug(s: str, n: int = 60) -> str:
    s = re.sub(r"[^a-zA-Z0-9_-]+", "-", s).strip("-")[:n]
    return s or "-"


def short_file(test_file: str) -> str:
    return Path(test_file).name if test_file else "-"


# Cross-cutting themes: short regex matchers that identify universal bug classes
# (so we can group findings across providers even when signatures differ)
THEMES = [
    (
        "CBC-PKCS5 padding oracle (Vaudenay)",
        re.compile(r"\b(CBC[-_ ]?PKCS5|Vaudenay|padding oracle)\b", re.I),
    ),
    (
        "NULL-pointer SIGSEGV family",
        re.compile(
            r"\b(NULL[-_ ]?pointer SIGSEGV|NULL[-_ ]?deref|null_data_with_nonzero_length|null_arg)\b",
            re.I,
        ),
    ),
    (
        "Op-termination lifecycle",
        re.compile(
            r"\b(op[-_ ]?termination|operation_active|operation_left_active|dangling op|CKR_OPERATION_ACTIVE)\b",
            re.I,
        ),
    ),
    (
        "Read-only attribute mutation accepted",
        re.compile(
            r"\b(read[-_ ]?only attr|CKA_CLASS read-only|CKA_MODULUS changed|non-atomic|partial[-_ ]?apply)\b",
            re.I,
        ),
    ),
    (
        "Trust-boundary attribute escalation",
        re.compile(
            r"\b(CKA_TRUSTED|CKA_WRAP_WITH_TRUSTED|CKA_ALWAYS_AUTHENTICATE|CKA_EXTRACTABLE.*ignored|CKA_SENSITIVE.*ignored|sensitivity leak)\b",
            re.I,
        ),
    ),
    (
        "Buffer-size protocol deviation",
        re.compile(
            r"\b(buffer[-_ ]?too[-_ ]?small|wrong pulSize|buffer_size_protocol|CKR_BUFFER_TOO_SMALL.*pulSize)\b",
            re.I,
        ),
    ),
    (
        "Wrong CKR for invalid signatures",
        re.compile(
            r"\b(CKR_FUNCTION_FAILED instead of CKR_SIGNATURE_INVALID|wrong CKR.*signature)\b", re.I
        ),
    ),
    (
        "Wrap/unwrap policy bypass",
        re.compile(
            r"\b(CKA_WRAP_TEMPLATE|CKA_UNWRAP_TEMPLATE|wrap[-_ ]?policy|wrap[-_ ]?with[-_ ]?trusted)\b",
            re.I,
        ),
    ),
    (
        "Advertised-but-not-operational mechanism",
        re.compile(
            r"\b(advertised but not operational|capability gap|CKM_.*not operational)\b", re.I
        ),
    ),
    (
        "RSA-PKCS1 accept-invalid (Bleichenbacher-class)",
        re.compile(r"\b(accept[-_ ]?invalid.*PKCS|Bleichenbacher|RSA[-_ ]?PKCS1.*accept)\b", re.I),
    ),
    (
        "Wrong-output / crypto-correctness",
        re.compile(
            r"\b(wrong output|wrong[-_ ]?output|Type[-_ ]?A|digest.*SHA.256.*empty|ignores IV)\b",
            re.I,
        ),
    ),
]


def theme_for(v: Verdict) -> str | None:
    text = f"{v.message} {v.evidence}"
    for name, pat in THEMES:
        if pat.search(text):
            return name
    return None


def render_index(verdicts: list[Verdict]) -> str:
    by_provider: dict[str, list[Verdict]] = defaultdict(list)
    for v in verdicts:
        by_provider[v.provider].append(v)

    # Top-line numbers
    crit = [v for v in verdicts if v.severity == "CRITICAL"]
    high = [v for v in verdicts if v.severity == "HIGH"]
    high_user_escalation = [v for v in high if v.routing == "USER_ESCALATION"]
    sections: list[str] = []
    sections.append("# Per-Failure Triage — Executive Summary\n")
    sections.append(
        "**Source:** `docs/findings/per-failure-triage/verdicts.jsonl` (effective view, superseded records removed)"
    )
    sections.append("**Date:** 2026-06-13")
    sections.append(
        "**Scope:** 7 providers × artifacts_base data (no fresh docker). See parent plan `docs/superpowers/plans/2026-06-13-per-failure-triage.md`.\n"
    )

    sections.append("## Headline counts\n")
    sections.append(f"- **{len(crit)} CRITICAL** findings")
    sections.append(
        f"- **{len(high)} HIGH** findings (of which **{len(high_user_escalation)}** routed USER_ESCALATION)"
    )
    sections.append(f"- **{len(verdicts)}** effective verdict records (superseded ones dropped)\n")

    sections.append("## Per-provider table\n")
    sections.append(
        "| Provider | Total | PROVIDER_BUG | KNOWN_ISSUE | SOFT_TOKEN_CAVEAT | HARNESS_BUG | UNKNOWN | CRITICAL | HIGH |"
    )
    sections.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for p in PROVIDERS:
        vs = by_provider.get(p, [])
        cats = Counter(v.category for v in vs)
        sevs = Counter(v.severity for v in vs)
        sections.append(
            f"| [{p}]({p}.md) | {len(vs)} | {cats['PROVIDER_BUG']} | {cats['KNOWN_ISSUE']} | "
            f"{cats['SOFT_TOKEN_CAVEAT']} | {cats['HARNESS_BUG']} | {cats['UNKNOWN']} | "
            f"{sevs['CRITICAL']} | {sevs['HIGH']} |"
        )
    sections.append("")

    # Top-priority findings across all providers
    sections.append("## Top-priority findings across all providers\n")
    top = sorted(
        [
            v
            for v in verdicts
            if v.severity in ("CRITICAL", "HIGH") and v.category in ("PROVIDER_BUG", "UPSTREAM_BUG")
        ],
        key=lambda v: (SEVERITY_ORDER[v.severity], v.provider),
    )
    sections.append("| Severity | Provider | Test file | Direction | Routing | Signature |")
    sections.append("|---|---|---|---|---|---|")
    for v in top[:40]:
        sections.append(
            f"| **{v.severity}** | {v.provider} | `{short_file(v.test_file)}` | {v.direction} | "
            f"{ROUTING_ICON.get(v.routing, '')} {v.routing} | `{v.signature[:24]}` |"
        )
    if len(top) > 40:
        sections.append(
            f"\n*…and {len(top) - 40} more CRITICAL/HIGH findings in per-provider reports.*\n"
        )
    else:
        sections.append("")

    # Cross-cutting themes
    sections.append("## Cross-cutting themes (universal patterns)\n")
    sections.append("See `_universal.md` for full analysis. Themes with multi-provider impact:\n")
    theme_to_provs: dict[str, set[str]] = defaultdict(set)
    theme_to_sev: dict[str, str] = {}
    for v in verdicts:
        t = theme_for(v)
        if t:
            theme_to_provs[t].add(v.provider)
            if SEVERITY_ORDER[v.severity] < SEVERITY_ORDER.get(theme_to_sev.get(t, "INFO"), 99):
                theme_to_sev[t] = v.severity
    sections.append("| Theme | Worst severity | Providers affected |")
    sections.append("|---|---|---|")
    for t in sorted(
        theme_to_provs, key=lambda x: (SEVERITY_ORDER[theme_to_sev[x]], -len(theme_to_provs[x]))
    ):
        provs = ", ".join(
            sorted(p.replace("-main", "").replace("-master", "") for p in theme_to_provs[t])
        )
        sections.append(f"| {t} | {theme_to_sev[t]} | {len(theme_to_provs[t])} — {provs} |")
    sections.append("")

    sections.append("## Per-provider reports\n")
    for p in PROVIDERS:
        sections.append(f"- [{p}]({p}.md)")
    sections.append("")
    sections.append("## Methodology and notes\n")
    sections.append(
        "- Records appended idempotently to `verdicts.jsonl`; superseded records filtered out here."
    )
    sections.append(
        "- `UNKNOWN` records are not classified; they appear in a trailing section per provider for follow-up."
    )
    sections.append(
        "- Per user direction (m0213-m0214), classification extension stopped on 2026-06-13; remaining UNKNOWNs will be classified by a different (in-tool) workflow.\n"
    )
    return "\n".join(sections)


def render_provider(provider: str, vs: list[Verdict]) -> str:
    sections: list[str] = []
    sections.append(f"# {provider} — Per-Failure Triage\n")
    sections.append(f"**Effective records:** {len(vs)}")
    cats = Counter(v.category for v in vs)
    sevs = Counter(v.severity for v in vs)
    sections.append(f"**Categories:** {dict(cats.most_common())}")
    sections.append(f"**Severities:** {dict(sevs.most_common())}\n")

    # Findings (excluding UNKNOWN and INFO noise)
    findings = [
        v
        for v in vs
        if v.category
        in ("PROVIDER_BUG", "UPSTREAM_BUG", "HARNESS_BUG", "SOFT_TOKEN_CAVEAT", "SPEC_AMBIGUITY")
        and v.severity != "INFO"
    ]
    findings.sort(
        key=lambda v: (SEVERITY_ORDER[v.severity], CATEGORY_ORDER[v.category], v.test_file)
    )

    sections.append(f"## Findings ({len(findings)})\n")
    sections.append("Ordered by severity then category.\n")

    # Group by test_file for compactness
    by_file: dict[str, list[Verdict]] = defaultdict(list)
    for v in findings:
        by_file[v.test_file].append(v)

    fid = 0
    for test_file in sorted(by_file):
        file_vs = by_file[test_file]
        sections.append(f"### `{short_file(test_file)}` ({len(file_vs)} findings)\n")
        for v in file_vs:
            fid += 1
            icon = ROUTING_ICON.get(v.routing, "")
            sections.append(f"#### F{fid:03d} [{v.severity}/{v.category}] — {icon} {v.routing}")
            sections.append(f"- **Signature:** `{v.signature}`")
            sections.append(
                f"- **Direction:** `{v.direction}` · **Outcome:** `{v.outcome}` · **Tests covered:** {v.group_size}"
            )
            sections.append(f"- **Example nodeid:** `{v.example_nodeid}`")
            msg = (v.message or "").strip()
            if msg:
                sections.append(f"- **Message:** {msg[:300]}")
            ev = (v.evidence or "").strip()
            if ev:
                sections.append(f"- **Evidence:** {ev[:500]}")
            sections.append("")
    sections.append("")

    # KNOWN_ISSUE summary (counts only, link to module-issues.md)
    known = [v for v in vs if v.category == "KNOWN_ISSUE"]
    if known:
        sections.append(
            f"## Already documented in `docs/module-issues.md` ({len(known)} findings)\n"
        )
        sections.append(
            "These records match an existing module-issues.md entry. Not re-listed here to avoid duplication; see `verdicts.jsonl` for individual pointers.\n"
        )

    # UNKNOWN (deferred)
    unknown = [v for v in vs if v.category == "UNKNOWN"]
    if unknown:
        sections.append(f"## Not yet classified ({len(unknown)} groups, DEFERRED)\n")
        sections.append(
            "Per user directive m0213-m0214, classification extension stopped. These will be classified by an in-tool workflow.\n"
        )
        sections.append("Top by size:")
        unknown_sorted = sorted(unknown, key=lambda v: -v.group_size)[:15]
        sections.append("| Group size | Direction | Test file | Signature |")
        sections.append("|---:|---|---|---|")
        for v in unknown_sorted:
            sections.append(
                f"| {v.group_size} | {v.direction} | `{short_file(v.test_file)}` | `{v.signature[:24]}` |"
            )
        sections.append("")
    return "\n".join(sections)


def render_universal(verdicts: list[Verdict]) -> str:
    sections: list[str] = []
    sections.append("# Cross-Provider Correlation\n")
    sections.append(
        "Universal patterns and provider-specific outliers, derived from `verdicts.jsonl`.\n"
    )

    # Group by theme
    theme_groups: dict[str, list[Verdict]] = defaultdict(list)
    for v in verdicts:
        t = theme_for(v)
        if t:
            theme_groups[t].append(v)

    sections.append("## Universal themes (multi-provider impact)\n")
    sections.append("| Theme | Severity | Providers | Count | Example finding |")
    sections.append("|---|---|---|---:|---|")
    for t in sorted(theme_groups, key=lambda x: -len({v.provider for v in theme_groups[x]})):
        vs = theme_groups[t]
        provs = sorted({v.provider.replace("-main", "").replace("-master", "") for v in vs})
        sev = min((v.severity for v in vs), key=lambda s: SEVERITY_ORDER[s])
        example = sorted(vs, key=lambda v: SEVERITY_ORDER[v.severity])[0]
        sections.append(
            f"| **{t}** | {sev} | {len(provs)} ({', '.join(provs)}) | {len(vs)} | "
            f"`{example.signature[:24]}` {short_file(example.test_file)} |"
        )
    sections.append("")

    # Provider-specific outliers (HIGH/CRITICAL findings unique to one provider)
    sections.append("## Provider-specific HIGH/CRITICAL outliers\n")
    sections.append(
        "Findings that appear on exactly one provider — likely real provider-specific bugs worth filing upstream.\n"
    )
    by_provider_high: dict[str, list[Verdict]] = defaultdict(list)
    for v in verdicts:
        if v.severity in ("CRITICAL", "HIGH") and v.category in ("PROVIDER_BUG", "UPSTREAM_BUG"):
            by_provider_high[v.provider].append(v)
    sections.append("| Provider | HIGH+CRITICAL count | Sample finding |")
    sections.append("|---|---:|---|")
    for p in PROVIDERS:
        vs = sorted(by_provider_high.get(p, []), key=lambda v: SEVERITY_ORDER[v.severity])
        if not vs:
            sections.append(f"| {p} | 0 | — |")
            continue
        ex = vs[0]
        sections.append(
            f"| {p} | {len(vs)} | `{short_file(ex.test_file)}` {ex.direction} — {ex.message[:80]} |"
        )
    sections.append("")

    # Routing summary
    sections.append("## Routing summary\n")
    routing = Counter(
        v.routing for v in verdicts if v.category in ("PROVIDER_BUG", "UPSTREAM_BUG", "HARNESS_BUG")
    )
    sections.append("| Routing | Records | What it means |")
    sections.append("|---|---:|---|")
    for r, n in routing.most_common():
        meaning = {
            "USER_ESCALATION": "Investigate immediately; security-sensitive",
            "PROVIDER_REPORT": "File as upstream bug report",
            "HARNESS_FIX": "Fix in pkcs11-check test code",
            "DOCS_ONLY": "Documented behaviour; no action",
            "MANUAL_REVIEW": "Needs human judgment",
        }.get(r, r)
        sections.append(f"| {r} | {n} | {meaning} |")
    sections.append("")
    return "\n".join(sections)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    verdicts = load_effective()

    (OUT / "_index.md").write_text(render_index(verdicts))
    (OUT / "_universal.md").write_text(render_universal(verdicts))

    by_provider: dict[str, list[Verdict]] = defaultdict(list)
    for v in verdicts:
        by_provider[v.provider].append(v)

    for p in PROVIDERS:
        (OUT / f"{p}.md").write_text(render_provider(p, by_provider.get(p, [])))

    print(f"Wrote {len(list(OUT.glob('*.md')))} report files to {OUT}")
    print(f"Effective verdicts: {len(verdicts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
