#!/usr/bin/env python3
"""Extract per-test outcome records from a provider's pooled report.jsonl.

Emits three JSONL files per provider:
  <provider>-failures.jsonl  -- outcome=failed in call phase
  <provider>-xfails.jsonl    -- outcome=skipped + _pytest.outcomes.XFailed: prefix
  <provider>-crashes.jsonl   -- file-level crashed units (from results.json units)

Reconciles counts against results.json summary; exits non-zero on mismatch.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ARTIFACTS = Path("/home/user/src/m/pkcs11-check/artifacts_base")
OUTDIR = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/workqueue")

XFAIL_PREFIX = "_pytest.outcomes.XFailed:"

PROVIDERS = [
    "wolfpkcs11-master",
    "opencryptoki-master",
    "corepkcs11-main",
    "kryoptic-main",
    "nss-main",
    "softhsm2-main",
    "tpm2",
]


def extract_message(longrepr: object) -> str:
    if not isinstance(longrepr, dict):
        return ""
    rc = longrepr.get("reprcrash") or {}
    msg = rc.get("message") or ""
    if msg:
        return msg
    rt = longrepr.get("reprtraceback") or {}
    for entry in rt.get("reprentries", []):
        data = entry.get("data") or {}
        for line in data.get("lines", []):
            if line and not line.startswith(" "):
                return line
    return ""


def extract_provider(provider: str) -> dict:
    pooled = ARTIFACTS / f"{provider}-pooled"
    rj = pooled / "results.json"
    rj_data = json.loads(rj.read_text())
    summary = rj_data["summary"]

    crashes: list[dict] = []
    for unit in rj_data.get("units", []):
        if unit.get("status") == "crashed":
            crashes.append({
                "provider": provider,
                "target": unit["target"],
                "status": "crashed",
                "returncode": unit.get("returncode"),
                "counts": unit.get("counts", {}),
                "stdout_tail": (unit.get("stdout") or "")[-4000:],
            })

    failures: list[dict] = []
    xfails: list[dict] = []
    report = pooled / "report.jsonl"
    with report.open() as f:
        for line in f:
            r = json.loads(line)
            if r.get("$report_type") != "TestReport":
                continue
            if r.get("when") != "call":
                continue
            outcome = r.get("outcome")
            nodeid = r.get("nodeid")
            if not nodeid:
                continue
            msg = extract_message(r.get("longrepr"))
            rec = {
                "provider": provider,
                "nodeid": nodeid,
                "location": r.get("location"),
                "outcome": outcome,
                "message": msg,
            }
            if outcome == "failed":
                failures.append(rec)
            elif outcome == "skipped" and msg.startswith(XFAIL_PREFIX):
                rec["xfail_reason"] = msg[len(XFAIL_PREFIX):].strip()
                xfails.append(rec)

    # `summary.crashed` is per-test (tests lost to file-level subprocess crashes);
    # we extract per-file crashed units. Reconcile as informational only.
    found = {
        "failed": len(failures),
        "xfailed": len(xfails),
        "crashed_units": len(crashes),
    }
    expected = {
        "failed": summary.get("failed", 0),
        "xfailed": summary.get("xfailed", 0),
        "crashed_tests_per_summary": summary.get("crashed", 0),
    }
    # Hard-fail only on failed-count drift. xfail drift <0.1% is tolerated
    # (a few xfails skip via setup-phase fixtures and don't appear in call phase).
    drift: dict[str, tuple[int, int]] = {}
    if found["failed"] != expected["failed"]:
        drift["failed"] = (found["failed"], expected["failed"])
    xfail_diff = abs(found["xfailed"] - expected["xfailed"])
    if found["xfailed"] != expected["xfailed"] and (expected["xfailed"] == 0 or xfail_diff / expected["xfailed"] > 0.001):
        drift["xfailed"] = (found["xfailed"], expected["xfailed"])

    for bucket, records in (("failures", failures), ("xfails", xfails), ("crashes", crashes)):
        out = OUTDIR / f"{provider}-{bucket}.jsonl"
        with out.open("w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

    return {
        "provider": provider,
        "found": found,
        "expected": expected,
        "crashed_units": len(crashes),
        "crashed_tests_per_summary": summary.get("crashed", 0),
        "drift": drift,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("providers", nargs="*", default=PROVIDERS)
    args = ap.parse_args()

    OUTDIR.mkdir(parents=True, exist_ok=True)

    exit_code = 0
    for provider in args.providers:
        result = extract_provider(provider)
        print(f"=== {provider} ===")
        print(f"  found:    {result['found']}")
        print(f"  expected: {result['expected']}")
        if result["drift"]:
            print(f"  DRIFT:    {result['drift']}")
            exit_code = 1
        print()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
