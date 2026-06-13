#!/usr/bin/env python3
"""Phase 6 bulk classifier for xfails.

Most xfail UNKNOWN records follow predictable patterns:
  - "advertised but not operational" → PROVIDER_BUG/LOW (capability gap)
  - "CKR_..." clean rejection of advertised mechanism → PROVIDER_BUG/LOW
  - documented quirk match → KNOWN_ISSUE/INFO

This script applies pattern rules to emit verdicts in bulk, leaving
genuinely ambiguous cases for manual Phase 6 subagent dispatch.

Idempotent: skips records already superseded by a #phase6 verdict.
"""
from __future__ import annotations

import datetime
import json
import re
import sys
from pathlib import Path

VERDICTS = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/verdicts.jsonl")


def load_verdicts() -> tuple[list[dict], set[str]]:
    """Return (all_verdicts, superseded_signatures)."""
    verdicts: list[dict] = []
    superseded: set[str] = set()
    with VERDICTS.open() as f:
        for line in f:
            v = json.loads(line)
            verdicts.append(v)
            if "supersedes" in v:
                superseded.add(v["supersedes"])
    return verdicts, superseded


# Pattern rules: (regex, category, severity, routing, evidence_template, note)
RULES: list[tuple[re.Pattern, str, str, str, str, str]] = [
    # Explicit capability gap message from classifier
    (
        re.compile(r"advertised but.*not operational", re.IGNORECASE),
        "PROVIDER_BUG", "LOW", "PROVIDER_REPORT",
        "Capability gap: {snippet}. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).",
        "phase6bulk: advertised-but-not-operational",
    ),
    # Keygen setup rejected
    (
        re.compile(r"advertised but.*keygen.*(?:rejected|not operational)", re.IGNORECASE),
        "PROVIDER_BUG", "LOW", "PROVIDER_REPORT",
        "Keygen capability gap: {snippet}.",
        "phase6bulk: keygen capability gap",
    ),
    # Vector replay: clean reject of advertised mechanism variant
    (
        re.compile(r"CKR_(?:MECHANISM_INVALID|KEY_TYPE_INCONSISTENT|MECHANISM_PARAM_INVALID|TEMPLATE_INCONSISTENT|ATTRIBUTE_TYPE_INVALID|FUNCTION_NOT_SUPPORTED)",
                   re.IGNORECASE),
        "PROVIDER_BUG", "LOW", "PROVIDER_REPORT",
        "Clean CKR rejection of advertised-mechanism variant: {snippet}. Direction = reject-valid → functional gap (LOW).",
        "phase6bulk: vector-replay capability gap",
    ),
    # Buffer-too-small / size-protocol clean rejection (test-side xfail)
    (
        re.compile(r"CKR_BUFFER_TOO_SMALL", re.IGNORECASE),
        "PROVIDER_BUG", "LOW", "PROVIDER_REPORT",
        "Buffer-protocol deviation: {snippet}.",
        "phase6bulk: buffer-protocol deviation",
    ),
    # RSA-OAEP / RSA-PSS hash variants (commonly documented)
    (
        re.compile(r"(?:OAEP|PSS).*SHA-?(?:224|256|384|512)|SHA-?(?:224|256|384|512).*(?:OAEP|PSS)", re.IGNORECASE),
        "PROVIDER_BUG", "LOW", "PROVIDER_REPORT",
        "RSA padding hash-variant gap: {snippet}. Module only supports subset of RFC 8017 hash/MGF combinations.",
        "phase6bulk: RSA-padding hash-variant gap",
    ),
]


def classify(message: str) -> tuple[str, str, str, str, str] | None:
    """Apply rules to a xfail message; return (cat, sev, route, evidence, note) or None."""
    msg = re.sub(r"^_pytest\.outcomes\.XFailed:\s*", "", message)
    snippet = msg[:240]
    for pat, cat, sev, route, tpl, note in RULES:
        if pat.search(msg):
            return cat, sev, route, tpl.format(snippet=snippet), note
    return None


def main() -> int:
    verdicts, superseded = load_verdicts()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Walk UNKNOWN xfail records
    new_lines: list[str] = []
    counts = {"matched": 0, "unmatched": 0, "superseded": 0, "non_unknown": 0}
    by_rule: dict[str, int] = {}

    for v in verdicts:
        if v.get("category") != "UNKNOWN":
            counts["non_unknown"] += 1
            continue
        if v["signature"] in superseded:
            counts["superseded"] += 1
            continue
        if v.get("outcome") != "xfail":
            continue  # only handle xfails
        result = classify(v.get("message", ""))
        if result is None:
            counts["unmatched"] += 1
            continue
        cat, sev, route, evidence, note = result
        new_v = {
            **v,
            "category": cat,
            "severity": sev,
            "evidence": evidence,
            "routing": route,
            "analyzed_at": now,
            "analyzer": "manual-phase6-bulk",
            "analyzer_note": note,
            "supersedes": v["signature"],
            "signature": v["signature"] + "#phase6",
        }
        new_lines.append(json.dumps(new_v))
        counts["matched"] += 1
        by_rule[note] = by_rule.get(note, 0) + 1

    print(f"Scan results:")
    for k, n in counts.items():
        print(f"  {k}: {n}")
    print(f"\nMatched by rule:")
    for note, n in sorted(by_rule.items(), key=lambda kv: -kv[1]):
        print(f"  {n:5d}  {note}")

    if new_lines:
        with VERDICTS.open("a") as f:
            for line in new_lines:
                f.write(line + "\n")
        print(f"\nAppended {len(new_lines)} bulk verdicts.")
    else:
        print("\nNo new verdicts to append.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
