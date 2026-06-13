#!/usr/bin/env python3
"""Phase 6 verdict emitter: append a superseding verdict for an UNKNOWN group.

Usage:
    python emit_phase6_verdict.py --signature sha1:xxxx \\
        --category PROVIDER_BUG --severity HIGH \\
        --evidence "..." --routing PROVIDER_REPORT \\
        --analyzer-note "manual phase6: <reason>"

Reads the existing verdict record matching --signature (must be UNKNOWN),
then appends a superseding record with category=PROVIDER_BUG (or other).
Idempotent: if a superseding record with signature "<sig>#phase6" already
exists, exits without appending.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

VERDICTS = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/verdicts.jsonl")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--signature", required=True, help="base signature (UNKNOWN record)")
    ap.add_argument(
        "--category",
        required=True,
        choices=[
            "PROVIDER_BUG",
            "UPSTREAM_BUG",
            "HARNESS_BUG",
            "KNOWN_ISSUE",
            "SPEC_AMBIGUITY",
            "SOFT_TOKEN_CAVEAT",
            "FALSE_POSITIVE",
        ],
    )
    ap.add_argument(
        "--severity", required=True, choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    )
    ap.add_argument("--evidence", required=True)
    ap.add_argument(
        "--routing",
        required=True,
        choices=["PROVIDER_REPORT", "HARNESS_FIX", "DOCS_ONLY", "MANUAL_REVIEW", "USER_ESCALATION"],
    )
    ap.add_argument("--analyzer-note", default="")
    args = ap.parse_args()

    new_sig = args.signature + "#phase6"
    base_record: dict | None = None
    existing_sigs: set[str] = set()
    with VERDICTS.open() as f:
        for line in f:
            if not line.strip():
                continue
            v = json.loads(line)
            existing_sigs.add(v["signature"])
            if v["signature"] == args.signature and v.get("category") == "UNKNOWN":
                base_record = v

    if base_record is None:
        print(f"ERROR: no UNKNOWN record with signature {args.signature!r}", file=sys.stderr)
        return 2

    if new_sig in existing_sigs:
        print(f"OK: superseding verdict {new_sig} already exists; skipping")
        return 0

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    new_v = {
        **base_record,
        "category": args.category,
        "severity": args.severity,
        "evidence": args.evidence,
        "routing": args.routing,
        "analyzed_at": now,
        "analyzer": "manual-phase6",
        "analyzer_note": args.analyzer_note,
        "supersedes": args.signature,
        "signature": new_sig,
    }
    with VERDICTS.open("a") as f:
        f.write(json.dumps(new_v) + "\n")
    print(f"OK: appended {new_sig} ({args.category}/{args.severity})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
