#!/usr/bin/env python3
"""Group workqueue records by signature.

Signature = sha1(provider + bucket + test_file + message_prefix + direction_tag)

  test_file      = nodeid without parametrize suffix and without line number
  message_prefix = first 60 chars of normalized message (whitespace-collapsed)
  direction_tag  = heuristic from message text:
                   ACCEPT_INVALID / REJECT_VALID / WRONG_OUTPUT / CLEAN_ERROR / CRASH / CAPABILITY_GAP / OTHER

The signature collapses e.g. 210 wycheproof RSA-OAEP tc-failed cases into ONE group.
Output: groups/<provider>-<bucket>-groups.json
  { "signature": {"signature":..., "size":N, "test_file":..., "direction":...,
                   "example_nodeid":..., "messages_sample":[...], "nodeids":[...] } }
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

WQ = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/workqueue")
OUTDIR = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/groups")

DIR_PATTERNS = [
    (r"accept(ing|ed)?\s+(an?\s+)?invalid|invalid\s+(ciphertext|signature|tag|key|padding).*CKR_OK|CKR_OK.*invalid|decrypt\s+successfully|encrypt\s+successfully", "ACCEPT_INVALID"),
    (r"reject(ing|ed)?\s+(a\s+)?valid|valid.*rejected|valid-tag.*rejected|valid\s+sig(nature)?\s+rejected|tc\d+-valid.*Unexpected\s+CK_RV", "REJECT_VALID"),
    (r"wrong\s+(output|digest|signature|ciphertext)|mismatch|expected\s+\S+\s+got\s+\S+|InvalidSignature|did\s+not\s+match", "WRONG_OUTPUT"),
    (r"crash|SIGSEGV|SIGABRT|signal\s+\d+|returncode", "CRASH"),
    (r"CK_RV\s+CKR_\w+|Unexpected\s+CK_RV|CKR_\w+", "CLEAN_ERROR"),
    (r"advertised\s+but\s+not\s+operational|not\s+operational|operability\s+probe|mechanism\s+operational\s+but|not\s+advertised|CAPABILITY_GAP|capability\s+absent", "CAPABILITY_GAP"),
]


def direction_of(msg: str) -> str:
    m = msg.lower()
    for pat, tag in DIR_PATTERNS:
        if re.search(pat, m, re.IGNORECASE):
            return tag
    return "OTHER"


def test_file_of(nodeid: str) -> str:
    return nodeid.split("::", 1)[0]


def message_prefix(msg: str, n: int = 40) -> str:
    collapsed = re.sub(r"\s+", " ", msg or "").strip()
    return collapsed[:n]


def signature(provider: str, bucket: str, test_file: str, msg_prefix: str, direction: str) -> str:
    h = hashlib.sha1()
    h.update(f"{provider}|{bucket}|{test_file}|{msg_prefix}|{direction}".encode())
    return f"sha1:{h.hexdigest()[:16]}"


def group_bucket(provider: str, bucket: str) -> dict:
    path = WQ / f"{provider}-{bucket}.jsonl"
    if not path.exists():
        return {}
    by_sig: dict[str, dict] = defaultdict(lambda: {
        "size": 0, "nodeids": [], "messages_sample": set(), "test_file": "", "direction": "",
        "provider": provider, "bucket": bucket, "signature": "",
    })
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        test_file = test_file_of(r["nodeid"])
        msg = r.get("message") or r.get("xfail_reason") or ""
        msg_prefix = message_prefix(msg)
        direction = direction_of(msg)
        sig = signature(provider, bucket, test_file, msg_prefix, direction)
        g = by_sig[sig]
        g["signature"] = sig
        g["size"] += 1
        g["nodeids"].append(r["nodeid"])
        if len(g["messages_sample"]) < 3:
            g["messages_sample"].add(msg[:300])
        g["test_file"] = test_file
        g["direction"] = direction
        g["provider"] = provider
        g["bucket"] = bucket
    for g in by_sig.values():
        g["messages_sample"] = sorted(g["messages_sample"])
        g["example_nodeid"] = g["nodeids"][0]
    return by_sig


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("providers", nargs="*")
    ap.add_argument("--buckets", nargs="*", default=["failures", "xfails"])
    args = ap.parse_args()
    providers = args.providers or [
        "wolfpkcs11-master", "opencryptoki-master", "corepkcs11-main",
        "kryoptic-main", "nss-main", "softhsm2-main", "tpm2",
    ]

    OUTDIR.mkdir(parents=True, exist_ok=True)
    grand_total = 0
    summary_lines = []
    for provider in providers:
        for bucket in args.buckets:
            groups = group_bucket(provider, bucket)
            if not groups:
                continue
            out = OUTDIR / f"{provider}-{bucket}-groups.json"
            payload = {
                "provider": provider,
                "bucket": bucket,
                "group_count": len(groups),
                "total_records": sum(g["size"] for g in groups.values()),
                "groups": sorted(groups.values(), key=lambda g: -g["size"]),
            }
            out.write_text(json.dumps(payload, indent=2))
            grand_total += payload["total_records"]
            line = f"{provider}/{bucket}: {payload['group_count']} groups, {payload['total_records']} records"
            summary_lines.append(line)
            print(line)
    print(f"Grand total: {grand_total} records grouped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
