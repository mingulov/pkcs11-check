#!/usr/bin/env python3
"""Cross-reference verdicts.jsonl against docs/module-issues.md.

For any verdict whose (provider, test_file, message_keyword) matches an existing
module-issues entry, append a follow-up verdict record with category=KNOWN_ISSUE
and severity ≤ INFO, pointing at the doc section.

This does NOT delete the original verdict — it appends a superseding record with
`supersedes` pointing back. Loop continuation rule: never delete.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
from pathlib import Path

VERDICTS = Path("/home/user/src/m/pkcs11-check/docs/findings/per-failure-triage/verdicts.jsonl")
MODULE_ISSUES = Path("/home/user/src/m/pkcs11-check/docs/module-issues.md")


GENERIC_WORDS = {
    # test category words — appear in many tests, don't discriminate
    "wycheproof",
    "acvp",
    "cctv",
    "vector",
    "vectors",
    "testcase",
    "tests",
    # crypto primitives — every test touches one
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "signature",
    "digest",
    "hash",
    "padding",
    "module",
    "mechanism",
    "session",
    "slot",
    "operation",
    "init",
    "update",
    "final",
    "single",
    "multi",
    "multipart",
    "streaming",
    # generic verbs/connectives
    "accepts",
    "returns",
    "instead",
    "supports",
    "affects",
    "detected",
    "calls",
    "passed",
    "false",
    "true",
    "missing",
    "broken",
    "wrong",
    "fails",
    "failure",
    "failures",
    "crash",
    "crashes",
    "crashed",
    "argument",
    "arguments",
    "attribute",
    "attributes",
    "template",
    "value",
    "input",
    "inputs",
    "output",
    "outputs",
    "result",
    "results",
    "expected",
    # generic spec words
    "spec",
    "specification",
    "compliance",
    "conformant",
    "conform",
    "advertised",
    "operational",
    "extractable",
    "sensitive",
    "always",
    # RSA family / common — too broad
    "rsa",
    "ecdsa",
    "eddsa",
    "ecdh",
    "aes",
    "hmac",
    "gcm",
    "ccm",
    "cbc",
    "ctr",
    "cfb",
    "ofb",
    "xts",
    "key",
    "keys",
    "block",
    "bits",
    # SHA family
    "sha1",
    "sha256",
    "sha384",
    "sha512",
    "sha-1",
    "sha-256",
    "sha3",
    # NSS / generic
    "nss",
    "softoken",
    # numbers / sizes
    "size",
    "length",
    "len",
    "count",
    "bytes",
}


def parse_module_issues() -> list[dict]:
    """Parse module-issues.md into a list of entries with discriminating keywords.

    Tightened post-over-match (2026-06-13): drop generic words, require multi-word
    discrimination. Also extract explicit test_X.py basenames when present.
    """
    entries: list[dict] = []
    if not MODULE_ISSUES.exists():
        return entries
    current_providers: list[str] = []
    current_section: str = ""
    for line in MODULE_ISSUES.read_text().splitlines():
        if line.startswith("## "):
            current_section = line.lstrip("# ").strip()
            current_providers = []
            for p in [
                "softhsm2",
                "kryoptic",
                "nss",
                "opencryptoki",
                "tpm2",
                "wolfpkcs11",
                "corepkcs11",
                "bouncyhsm",
            ]:
                if p in current_section.lower():
                    current_providers.append(p)
        elif line.startswith("### ") or line.startswith("- "):
            text = line.lstrip("#- ").strip()
            # Extract explicit test_X.py basenames (high-precision match)
            test_files = re.findall(r"test_[a-z0-9_]+\.py", text.lower())
            # Discriminating keywords: long words not in the generic stoplist
            keywords = [
                w for w in re.split(r"\W+", text.lower()) if len(w) >= 6 and w not in GENERIC_WORDS
            ][:12]
            entries.append(
                {
                    "providers": list(current_providers),
                    "section": current_section,
                    "text": text,
                    "test_files": test_files,
                    "keywords": keywords,
                }
            )
    return entries


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    entries = parse_module_issues()
    print(f"Loaded {len(entries)} module-issues entries")

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    new_lines: list[str] = []
    n_marked = 0
    n_already = 0

    for line in VERDICTS.read_text().splitlines():
        if not line.strip():
            continue
        v = json.loads(line)
        if v.get("category") == "KNOWN_ISSUE":
            n_already += 1
            continue
        provider_base = v["provider"].replace("-main", "").replace("-master", "")
        test_file = v.get("test_file", "")
        # Basename match is the high-precision signal: "test_wycheproof.py"
        # in module-issues.md vs. in the verdict's test_file.
        test_file_base = Path(test_file).name.lower() if test_file else ""
        msg = (v.get("message") or "").lower()

        for e in entries:
            if e["providers"] and provider_base not in e["providers"]:
                continue
            # Match strategy (any of):
            #   (a) explicit test_X.py basename match (high precision)
            #   (b) 3+ discriminating keywords present (len>=6, non-generic)
            tf_match = bool(test_file_base and test_file_base in e["test_files"])
            kw_hits = sum(1 for k in e["keywords"] if k in msg or k in test_file.lower())
            kw_match = kw_hits >= 3
            if not (tf_match or kw_match):
                continue
            basis = "test_file basename" if tf_match else f"{kw_hits} keyword hits"
            superseded = dict(v)
            new_v = {
                **v,
                "category": "KNOWN_ISSUE",
                "severity": "INFO",
                "evidence": f"Already documented in docs/module-issues.md §'{e['section']}' ({basis}): \"{e['text'][:120]}\"",
                "routing": "DOCS_ONLY",
                "analyzed_at": now,
                "analyzer": "auto-reconcile",
                "supersedes": v["signature"],
                "signature": v["signature"] + "#known",
            }
            new_lines.append(json.dumps(new_v))
            n_marked += 1
            break

    print(f"Already KNOWN_ISSUE: {n_already}")
    print(f"Newly marked KNOWN_ISSUE: {n_marked}")
    if not args.dry_run and new_lines:
        with VERDICTS.open("a") as f:
            for line in new_lines:
                f.write(line + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
