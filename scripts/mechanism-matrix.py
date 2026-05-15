#!/usr/bin/env python3
"""Generate mechanism matrix from test results.

Parses JUnit XML test results from multiple modules to produce a CSV
showing mechanism × module × pass/skip/fail/xfail.

Usage:
    # First, run tests with --junitxml:
    SOFTHSM2_CONF=/tmp/pkcs11-check-softhsm2.conf uv run pytest src/pkcs11_check/testcases/ \
      --p11-module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --p11-pin=1234 \
      --junitxml=results/softhsm2.xml -q --benchmark-disable

    # Then generate the matrix:
    uv run python scripts/mechanism-matrix.py results/*.xml
"""

from __future__ import annotations

import csv
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path


def parse_junit_xml(path: Path) -> dict[str, str]:
    """Parse JUnit XML, return {testname: outcome}."""
    tree = ET.parse(path)
    root = tree.getroot()

    results: dict[str, str] = {}
    for testcase in root.iter("testcase"):
        name = testcase.get("classname", "") + "::" + testcase.get("name", "")

        # Determine outcome
        if testcase.find("failure") is not None:
            results[name] = "FAIL"
        elif testcase.find("error") is not None:
            results[name] = "ERROR"
        elif testcase.find("skipped") is not None:
            results[name] = "SKIP"
        else:
            results[name] = "PASS"

    return results


def extract_module_name(path: Path) -> str:
    """Extract module name from filename (e.g., 'softhsm2' from 'softhsm2.xml')."""
    return path.stem.split("-")[0] if "-" in path.stem else path.stem


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: mechanism-matrix.py results/*.xml", file=sys.stderr)
        sys.exit(1)

    xml_files = [Path(f) for f in sys.argv[1:]]

    # Parse all result files
    all_results: dict[str, dict[str, str]] = {}
    for xml_file in xml_files:
        module_name = extract_module_name(xml_file)
        all_results[module_name] = parse_junit_xml(xml_file)

    # Collect all test names
    all_tests: set[str] = set()
    for results in all_results.values():
        all_tests.update(results.keys())

    # Group by test file (mechanism area)
    file_groups: dict[str, list[str]] = defaultdict(list)
    for test_name in sorted(all_tests):
        # Extract file from classname
        parts = test_name.split("::")
        file_part = parts[0].split(".")[-1] if "." in parts[0] else parts[0]
        file_groups[file_part].append(test_name)

    # Output CSV
    modules = sorted(all_results.keys())
    writer = csv.writer(sys.stdout)
    writer.writerow(["Test Area", "Test", *modules])

    for file_area, tests in sorted(file_groups.items()):
        for test_name in sorted(tests):
            short_name = test_name.split("::")[-1] if "::" in test_name else test_name
            row = [file_area, short_name]
            for module in modules:
                outcome = all_results[module].get(test_name, "-")
                row.append(outcome)
            writer.writerow(row)

    # Summary
    print(file=sys.stderr)
    for module in modules:
        results = all_results[module]
        passed = sum(1 for v in results.values() if v == "PASS")
        failed = sum(1 for v in results.values() if v == "FAIL")
        skipped = sum(1 for v in results.values() if v == "SKIP")
        errored = sum(1 for v in results.values() if v == "ERROR")
        total = len(results)
        print(
            f"{module}: {passed} pass, {failed} fail, {skipped} skip, "
            f"{errored} error / {total} total",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
