#!/usr/bin/env python3
"""Enumerate all mechanisms for a PKCS#11 module and report coverage gaps.

Usage:
    uv run python scripts/mechanism-audit.py --module /path/to.so [--pin 1234]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import pkcs11


def get_tested_mechanisms() -> set[str]:
    """Scan test files for Mechanism.XXX references."""
    testcases_dir = Path("src/pkcs11_check/testcases")
    pattern = re.compile(r"Mechanism\.(\w+)")
    tested: set[str] = set()
    for f in testcases_dir.glob("test_*.py"):
        for m in pattern.findall(f.read_text()):
            tested.add(m)
    return tested


def main() -> None:
    parser = argparse.ArgumentParser(description="PKCS#11 mechanism audit")
    parser.add_argument("--module", required=True, help="Path to PKCS#11 .so")
    parser.add_argument("--pin", default=None, help="User PIN")
    parser.add_argument("--slot", type=int, default=0, help="Slot index")
    args = parser.parse_args()

    lib = pkcs11.lib(args.module)
    lib.initialize()

    try:
        slots = lib.get_slots(token_present=True)
        if not slots:
            slots = lib.get_slots(token_present=False)
        if args.slot >= len(slots):
            print(f"Slot {args.slot} not found (available: {len(slots)})")
            sys.exit(1)

        slot = slots[args.slot]
        mechs = slot.get_mechanisms()

        tested = get_tested_mechanisms()

        print(f"# Mechanism Audit: {Path(args.module).name}")
        print("")
        print(f"Total mechanisms: {len(mechs)}")
        print(f"Tested mechanisms: {len(tested)}")
        print("")

        supported = []
        vendor = []
        for m in sorted(mechs, key=lambda x: x.value if hasattr(x, "value") else int(x)):
            name = m.name if hasattr(m, "name") else f"0x{int(m):08x}"
            val = m.value if hasattr(m, "value") else int(m)

            try:
                info = slot.get_mechanism_info(m)
                min_key = info.min_key_length if hasattr(info, "min_key_length") else "?"
                max_key = info.max_key_length if hasattr(info, "max_key_length") else "?"
                flags = info.flags if hasattr(info, "flags") else 0
            except Exception:
                min_key = max_key = "?"
                flags = 0

            is_vendor = val >= 0x80000000
            is_tested = name in tested
            entry = {
                "name": name,
                "value": val,
                "min_key": min_key,
                "max_key": max_key,
                "flags": flags,
                "tested": is_tested,
                "vendor": is_vendor,
            }

            if is_vendor:
                vendor.append(entry)
            else:
                supported.append(entry)

        # Standard mechanisms
        print("## Standard Mechanisms")
        print("")
        print("| Mechanism | Key Size | Tested | Flags |")
        print("|-----------|----------|--------|-------|")
        for e in supported:
            status = "✓" if e["tested"] else "**GAP**"
            print(f"| {e['name']} | {e['min_key']}-{e['max_key']} | {status} | 0x{e['flags']:x} |")

        # Coverage gaps
        gaps = [e for e in supported if not e["tested"]]
        if gaps:
            print("")
            print(f"## Coverage Gaps ({len(gaps)} untested)")
            print("")
            for e in gaps:
                print(f"- {e['name']} (key size {e['min_key']}-{e['max_key']})")

        # Vendor mechanisms
        if vendor:
            print("")
            print(f"## Vendor-Defined Mechanisms ({len(vendor)})")
            print("")
            for e in vendor:
                print(
                    f"- 0x{e['value']:08x} ({e['name']}) — "
                    f"key size {e['min_key']}-{e['max_key']}"
                )

    finally:
        lib.finalize()


if __name__ == "__main__":
    main()
