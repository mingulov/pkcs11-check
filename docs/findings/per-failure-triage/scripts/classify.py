#!/usr/bin/env python3
"""Apply decision tree to groups, append verdicts to verdicts.jsonl.

First pass: automated rules. Anything not confidently classified gets
category=UNKNOWN and routed to Phase 6 manual deep-dive.

Idempotent: skips signatures already present in verdicts.jsonl.
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path

GROUPS = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/groups")
VERDICTS = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/verdicts.jsonl")

# Automated direction → category/severity table (per AGENTS.md classification model)
AUTO_RULES = [
    (r"security/test_ffi_length_boundary|security/test_arithmetic_overflow|0x7fff{3,}|0xffff{4,}|0x7fffffffffffffff",
     "SOFT_TOKEN_CAVEAT", "MEDIUM", "DOCS_ONLY",
     "UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens."),
    (r"advertised\s+but\s+not\s+operational|mechanism\s+operational\s+but",
     "PROVIDER_BUG", "LOW", "PROVIDER_REPORT",
     "Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery."),
    (r"ML-DSA|ML_KEM|MLKEM|SLH-DSA|SLHDSA|ML-DSA-|ML-KEM-|ml_dsa|ml_kem",
     "UNKNOWN", "MEDIUM", "MANUAL_REVIEW",
     "PQC mechanism. Possible harness-vector bug PC-2 (see findings-summary-2026-06-10.md). Manual review required."),
    (r"rsa_pkcs1_decrypt.*accept|PKCS#?1.*accept.*invalid|PKCS1.*Bleichenbauer|PKCS1.* pkcs1.* decrypt",
     "SOFT_TOKEN_CAVEAT", "HIGH", "DOCS_ONLY",
     "Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access)."),
    (r"AES-CBC.*PAD|CBC.*padding\s+oracle|Vaudenay|tc\d+-invalid.*decrypt\s+successfully",
     "PROVIDER_BUG", "HIGH", "PROVIDER_REPORT",
     "Vaudenay padding oracle: AES-CBC-PAD accepts invalid padding. Real provider bug."),
    (r"OAEP.*Manger|OAEP.*accept.*invalid|Manger",
     "PROVIDER_BUG", "HIGH", "PROVIDER_REPORT",
     "Manger oracle: RSA-OAEP non-uniform errors. Real provider bug."),
    (r"reject.*valid.*tag|valid-tag.*rejected|valid.*CCM.*reject|valid.*GCM.*reject|valid-tag\s+CCM|valid-tag\s+GCM",
     "PROVIDER_BUG", "LOW", "PROVIDER_REPORT",
     "Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle."),
]


def load_existing_signatures() -> set[str]:
    if not VERDICTS.exists():
        return set()
    sigs: set[str] = set()
    for line in VERDICTS.read_text().splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
            if r.get("signature"):
                sigs.add(r["signature"])
        except json.JSONDecodeError:
            continue
    return sigs


def classify_group(g: dict) -> dict | None:
    """Return a verdict dict, or None if no rule matched."""
    text = g["test_file"] + " " + " ".join(g.get("messages_sample") or [])
    for pat, cat, sev, routing, evidence in AUTO_RULES:
        if re.search(pat, text, re.IGNORECASE):
            return {
                "category": cat,
                "severity": sev,
                "routing": routing,
                "evidence": evidence,
                "analyzer": "auto-classifier",
            }
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", required=True)
    ap.add_argument("--bucket", required=True, choices=["failures", "xfails", "xpassed"])
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    gf = GROUPS / f"{args.provider}-{args.bucket}-groups.json"
    if not gf.exists():
        print(f"no groups file: {gf}", file=sys.stderr)
        return 1
    data = json.loads(gf.read_text())

    existing = load_existing_signatures()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    n_new = n_unknown = n_skipped = 0
    out_lines: list[str] = []
    for g in data["groups"]:
        if g["signature"] in existing:
            n_skipped += 1
            continue
        if args.limit and n_new >= args.limit:
            break

        verdict = classify_group(g)
        if verdict is None:
            verdict = {
                "category": "UNKNOWN",
                "severity": "MEDIUM",
                "routing": "MANUAL_REVIEW",
                "evidence": "No auto-rule matched. Phase 6 manual deep-dive required.",
                "analyzer": "auto-classifier:unmatched",
            }
            n_unknown += 1

        rec = {
            "provider": args.provider,
            "nodeid": f"<group:{g['signature']}>",
            "signature": g["signature"],
            "outcome": args.bucket.rstrip("s"),  # failure / xfail / xpassed
            "message": (g.get("messages_sample") or [""])[0][:500],
            "test_file": g["test_file"],
            "direction": g["direction"],
            "group_id": f"{args.provider}/{g['direction']}/{g['test_file']}#{g['signature'][-8:]}",
            "group_size": g["size"],
            "example_nodeid": g.get("example_nodeid"),
            "analyzed_at": now,
            **verdict,
        }
        out_lines.append(json.dumps(rec))
        n_new += 1

    if not args.dry_run and out_lines:
        with VERDICTS.open("a") as f:
            for line in out_lines:
                f.write(line + "\n")

    print(f"{args.provider}/{args.bucket}: new={n_new} unknown={n_unknown} skipped(already-done)={n_skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
