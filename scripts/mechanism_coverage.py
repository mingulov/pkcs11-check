#!/usr/bin/env python3
"""Mechanism coverage report — compare advertised mechanisms against test coverage.

Usage:
    uv run python scripts/mechanism_coverage.py --module /path/to.so [--slot 0] [--pin 1234]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.bootstrap import get_slot_ids
from pkcs11_check.raw.metadata_std import MECHANISM_NAMES
from pkcs11_check.raw.recipes import get_mechanism_list
from pkcs11_check.raw.types_std import CKR_OK

_TESTCASES_DIR = Path(__file__).resolve().parent.parent / "src" / "pkcs11_check" / "testcases"


def _scan_test_references() -> dict[str, set[str]]:
    """Scan testcases/ for CKM_* mechanism references.

    Returns {mech_name: {file_paths}} for both full CKM_* and short forms.
    """
    ckm_pattern = re.compile(r"\bCKM_([A-Z0-9_]+)\b")
    refs: dict[str, set[str]] = {}

    for f in sorted(_TESTCASES_DIR.rglob("*.py")):
        try:
            text = f.read_text()
        except OSError:
            continue
        rel = str(f.relative_to(_TESTCASES_DIR.parent.parent.parent))
        for match in ckm_pattern.finditer(text):
            full_name = f"CKM_{match.group(1)}"
            refs.setdefault(full_name, set()).add(rel)
            refs.setdefault(match.group(1), set()).add(rel)

    return refs


def _dedicated_test_files() -> set[str]:
    """Return set of mechanism names (CKM_* and short) that have dedicated test files."""
    dedicated: set[str] = set()
    for f in _TESTCASES_DIR.glob("test_*.py"):
        stem = f.stem.removeprefix("test_").upper()
        dedicated.add(f"CKM_{stem}")
        dedicated.add(stem)
    return dedicated


def _has_coverage(name: str, refs: dict[str, set[str]]) -> bool:
    if name in refs:
        return True
    short = name[4:] if name.startswith("CKM_") else name
    full = f"CKM_{short}" if not name.startswith("CKM_") else name
    return short in refs or full in refs


def main() -> None:
    parser = argparse.ArgumentParser(description="PKCS#11 mechanism coverage report")
    parser.add_argument("--module", required=True, help="Path to PKCS#11 module (.so)")
    parser.add_argument("--slot", type=int, default=0, help="Slot index (default: 0)")
    parser.add_argument("--pin", default=None, help="User PIN")
    args = parser.parse_args()

    raw = RawPKCS11.from_lib(args.module)
    rv = raw.C_Initialize()
    if rv != CKR_OK:
        print(f"C_Initialize failed: 0x{rv:08x}", file=sys.stderr)
        sys.exit(1)

    try:
        slots = get_slot_ids(raw)
        if not slots:
            print("No slots found", file=sys.stderr)
            sys.exit(1)
        if args.slot >= len(slots):
            print(f"Slot {args.slot} not found (available: {len(slots)})", file=sys.stderr)
            sys.exit(1)
        slot_id = slots[args.slot]
        mech_values = get_mechanism_list(raw, slot_id)
    finally:
        raw.C_Finalize()

    refs = _scan_test_references()
    dedicated = _dedicated_test_files()

    advertised_mechs: list[tuple[str, int]] = []
    for val in mech_values:
        name = MECHANISM_NAMES.get(val, "")
        if name:
            advertised_mechs.append((name, val))

    with_dedicated = 0
    referenced = 0
    no_coverage: list[tuple[str, int]] = []
    seen: set[str] = set()

    for name, val in advertised_mechs:
        key = name if name.startswith("CKM_") else f"CKM_{name}"
        if key in seen:
            continue
        seen.add(key)

        if _has_coverage(name, dedicated):
            with_dedicated += 1
        if _has_coverage(name, refs):
            referenced += 1
        elif not _has_coverage(name, dedicated):
            no_coverage.append((name, val))

    print("=== Mechanism Coverage Report ===")
    print(f"Advertised: {len(seen)}")
    print(f"With dedicated test file: {with_dedicated}")
    print(f"Referenced in tests: {referenced}")
    print(f"No test coverage: {len(no_coverage)}")
    if no_coverage:
        print("\nUncovered mechanisms:")
        for name, val in sorted(no_coverage):
            print(f"  {name} (0x{val:08x})")


if __name__ == "__main__":
    main()
