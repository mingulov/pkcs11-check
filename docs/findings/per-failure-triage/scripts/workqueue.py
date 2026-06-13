#!/usr/bin/env python3
"""Emit Phase 6 work-queue: UNKNOWN verdicts grouped by (provider, test_file).

Each work item is a bucket containing all UNKNOWN verdict records for one
(provider, test_file) pair. The subagent dispatching model is:
  - One subagent per bucket (small buckets are batched together)
  - Subagent reads the test code + sample stdout, classifies each group,
    returns appended verdict records

Priority order (highest first):
  1. ACCEPT_INVALID/WRONG_OUTPUT failures (crypto-correctness breaks)
  2. CRASH failures (real crashes beyond Phase 1)
  3. REJECT_VALID failures (over-strict rejection — LOW but provider bug)
  4. CLEAN_ERROR/OTHER failures (need investigation)
  5. CRASH xfails (rare)
  6. ACCEPT_INVALID/WRONG_OUTPUT xfails
  7. REJECT_VALID xfails (advertised-but-not-operational)
  8. CLEAN_ERROR xfails (bulk of work)
  9. OTHER xfails

Idempotent: emits the same work-queue given the same verdicts.jsonl.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

VERDICTS = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/verdicts.jsonl")
OUT = Path(
    "/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/workqueue/phase6-buckets.json"
)

PRIORITY = {
    # failures (highest priority)
    ("failure", "ACCEPT_INVALID"): 10,
    ("failure", "WRONG_OUTPUT"): 11,
    ("failure", "CRASH"): 12,
    ("failure", "REJECT_VALID"): 13,
    ("failure", "CLEAN_ERROR"): 14,
    ("failure", "OTHER"): 15,
    # xfails (lower priority)
    ("xfail", "CRASH"): 20,
    ("xfail", "ACCEPT_INVALID"): 21,
    ("xfail", "WRONG_OUTPUT"): 22,
    ("xfail", "REJECT_VALID"): 23,
    ("xfail", "CLEAN_ERROR"): 24,
    ("xfail", "OTHER"): 25,
}


def bucket_priority(records: list[dict]) -> int:
    """Lowest priority number among records = bucket's priority."""
    return min(PRIORITY.get((r["outcome"], r["direction"]), 99) for r in records)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-size", type=int, default=1)
    ap.add_argument("--limit", type=int, default=0, help="0 = no limit")
    ap.add_argument("--priority-min", type=int, default=0, help="only priority >= this")
    ap.add_argument("--priority-max", type=int, default=99, help="only priority <= this")
    args = ap.parse_args()

    # First pass: collect all signatures that have been superseded
    superseded: set[str] = set()
    with VERDICTS.open() as f:
        for line in f:
            v = json.loads(line)
            if "supersedes" in v:
                superseded.add(v["supersedes"])

    # Group UNKNOWN records by (provider, test_file), skipping superseded ones
    buckets: dict[tuple[str, str], list[dict]] = defaultdict(list)
    with VERDICTS.open() as f:
        for line in f:
            v = json.loads(line)
            if v.get("category") != "UNKNOWN":
                continue
            if v["signature"] in superseded:
                continue
            key = (v["provider"], v["test_file"])
            buckets[key].append(v)

    # Sort buckets by priority then by descending size
    items = [
        {
            "provider": key[0],
            "test_file": key[1],
            "record_count": len(records),
            "group_size_sum": sum(r.get("group_size", 1) for r in records),
            "priority": bucket_priority(records),
            "groups": [
                {
                    "signature": r["signature"],
                    "direction": r["direction"],
                    "outcome": r["outcome"],
                    "group_size": r.get("group_size", 1),
                    "message": r.get("message", "")[:300],
                    "example_nodeid": r.get("example_nodeid", ""),
                }
                for r in records
            ],
        }
        for key, records in buckets.items()
    ]
    items.sort(key=lambda b: (b["priority"], -b["group_size_sum"]))

    if args.min_size > 1:
        items = [b for b in items if b["record_count"] >= args.min_size]
    items = [b for b in items if args.priority_min <= b["priority"] <= args.priority_max]
    if args.limit > 0:
        items = items[: args.limit]

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(items, indent=2))
    print(f"Wrote {len(items)} buckets to {OUT}")

    # Summary
    from collections import Counter

    pri_count = Counter(b["priority"] for b in items)
    print("\nBuckets per priority tier:")
    for pri in sorted(pri_count):
        # reverse-lookup label
        label = next(
            (f"{outcome}/{direction}" for (outcome, direction), p in PRIORITY.items() if p == pri),
            f"tier-{pri}",
        )
        print(f"  {pri:2d}  {label:25s}: {pri_count[pri]:3d} buckets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
