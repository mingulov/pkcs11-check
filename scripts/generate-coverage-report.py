#!/usr/bin/env python3
"""Generate mechanism coverage report from test metadata.

Scans test files for mechanism usage and cross-references with
the PKCS#11 mechanism list to produce a coverage summary.

Usage:
    uv run python scripts/generate-coverage-report.py > docs/test-coverage-generated.md
"""

from __future__ import annotations

import re
from pathlib import Path

TESTCASES_DIR = Path("src/pkcs11_check/testcases")


def find_mechanisms_in_tests() -> dict[str, set[str]]:
    """Scan test files for Mechanism.XXX usage, return {mechanism: {files}}."""
    mech_pattern = re.compile(r"Mechanism\.(\w+)")
    mechanisms: dict[str, set[str]] = {}

    for test_file in sorted(TESTCASES_DIR.glob("test_*.py")):
        content = test_file.read_text()
        for match in mech_pattern.finditer(content):
            mech_name = match.group(1)
            if mech_name not in mechanisms:
                mechanisms[mech_name] = set()
            mechanisms[mech_name].add(test_file.stem)

    return mechanisms


def find_keytypes_in_tests() -> dict[str, set[str]]:
    """Scan test files for KeyType.XXX usage, return {keytype: {files}}."""
    kt_pattern = re.compile(r"KeyType\.(\w+)")
    keytypes: dict[str, set[str]] = {}

    for test_file in sorted(TESTCASES_DIR.glob("test_*.py")):
        content = test_file.read_text()
        for match in kt_pattern.finditer(content):
            kt_name = match.group(1)
            if kt_name not in keytypes:
                keytypes[kt_name] = set()
            keytypes[kt_name].add(test_file.stem)

    return keytypes


def count_tests() -> dict[str, int]:
    """Count test functions per file."""
    test_pattern = re.compile(r"^\s+def (test_\w+)", re.MULTILINE)
    # Also count parametrized top-level test functions
    top_pattern = re.compile(r"^def (test_\w+)", re.MULTILINE)
    counts: dict[str, int] = {}

    for test_file in sorted(TESTCASES_DIR.glob("test_*.py")):
        content = test_file.read_text()
        methods = test_pattern.findall(content)
        top_funcs = top_pattern.findall(content)
        counts[test_file.stem] = len(methods) + len(top_funcs)

    return counts


def find_markers_in_tests() -> dict[str, set[str]]:
    """Scan for pytest markers per file."""
    marker_pattern = re.compile(r"pytest\.mark\.(\w+)")
    markers: dict[str, set[str]] = {}

    for test_file in sorted(TESTCASES_DIR.glob("test_*.py")):
        content = test_file.read_text()
        file_markers = set()
        for match in marker_pattern.finditer(content):
            m = match.group(1)
            if m not in ("parametrize", "skipif", "skip", "xfail", "timeout"):
                file_markers.add(m)
        if file_markers:
            markers[test_file.stem] = file_markers

    return markers


def main() -> None:
    mechanisms = find_mechanisms_in_tests()
    keytypes = find_keytypes_in_tests()
    test_counts = count_tests()
    markers = find_markers_in_tests()

    total_files = len(test_counts)
    total_tests = sum(test_counts.values())

    print("# Test Coverage Report (Auto-Generated)")
    print()
    print(f"Generated from {total_files} test files, {total_tests} test functions.")
    print()

    # Mechanism coverage
    print("## Mechanism Coverage")
    print()
    print(f"{len(mechanisms)} mechanisms referenced across test files.")
    print()
    print("| Mechanism | Test Files |")
    print("|-----------|------------|")

    # Group by category
    categories: dict[str, list[tuple[str, set[str]]]] = {
        "AES": [],
        "RSA": [],
        "EC/ECDSA": [],
        "SHA/Digest": [],
        "HMAC": [],
        "DH": [],
        "EdDSA": [],
        "PQC": [],
        "KDF": [],
        "Other": [],
    }

    for mech, files in sorted(mechanisms.items()):
        if mech.startswith("AES"):
            categories["AES"].append((mech, files))
        elif mech.startswith("RSA") or mech.startswith("SHA") and "RSA" in mech:
            categories["RSA"].append((mech, files))
        elif mech.startswith("ECDSA") or mech.startswith("EC_"):
            categories["EC/ECDSA"].append((mech, files))
        elif mech.startswith("SHA") or mech == "MD5":
            categories["SHA/Digest"].append((mech, files))
        elif "HMAC" in mech:
            categories["HMAC"].append((mech, files))
        elif "DH" in mech:
            categories["DH"].append((mech, files))
        elif "EDDSA" in mech or "ED25519" in mech or "ED448" in mech:
            categories["EdDSA"].append((mech, files))
        elif "ML_" in mech or "SLH_" in mech or "KEM" in mech:
            categories["PQC"].append((mech, files))
        elif "HKDF" in mech or "DERIVE" in mech or "PBKD" in mech:
            categories["KDF"].append((mech, files))
        else:
            categories["Other"].append((mech, files))

    for _cat_name, cat_mechs in categories.items():
        if not cat_mechs:
            continue
        for mech, files in sorted(cat_mechs):
            file_list = ", ".join(sorted(f.replace("test_", "") for f in files))
            print(f"| {mech} | {file_list} |")

    # Key type coverage
    print()
    print("## Key Type Coverage")
    print()
    print("| Key Type | Test Files |")
    print("|----------|------------|")
    for kt, files in sorted(keytypes.items()):
        file_list = ", ".join(sorted(f.replace("test_", "") for f in files))
        print(f"| {kt} | {file_list} |")

    # Test file summary
    print()
    print("## Test File Summary")
    print()
    print("| File | Tests | Markers |")
    print("|------|-------|---------|")
    for fname, count in sorted(test_counts.items()):
        file_markers = markers.get(fname, set())
        marker_str = ", ".join(sorted(file_markers)) if file_markers else "-"
        print(f"| {fname} | {count} | {marker_str} |")

    print()
    print(f"**Total: {total_files} files, {total_tests} test functions**")


if __name__ == "__main__":
    main()
