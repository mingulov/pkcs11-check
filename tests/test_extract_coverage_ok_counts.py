"""extract_coverage_from_jsonl must carry function_coverage.ok_counts through the merge.

Regression for the hollow-pass oracle: the plugin writes per-file ok_counts (CKR_OK
counts per C_* function) into each CoverageReport, and quality_audit reads
coverage["function_coverage"]["ok_counts"] as the oracle's productive-invocation numerator.
The cross-file merge dropped that key, so productive_ok was always {} and every claimed
operation looked hollow. This test locks the merge to preserve + sum ok_counts.
"""

from __future__ import annotations

import json
from pathlib import Path

from pkcs11_check.core.file_runner import extract_coverage_from_jsonl


def _coverage_line(ok_counts: dict[str, int], called_counts: dict[str, int]) -> str:
    return json.dumps(
        {
            "$report_type": "CoverageReport",
            "function_coverage": {
                "available": 10,
                "called_names": sorted(called_counts),
                "called_counts": called_counts,
                "ok_counts": ok_counts,
                "uncalled_names": [],
            },
            "mechanism_coverage": {},
        }
    )


def test_extract_coverage_merges_and_sums_ok_counts(tmp_path: Path) -> None:
    p = tmp_path / "report.jsonl"
    p.write_text(
        _coverage_line({"C_Sign": 3, "C_Verify": 5}, {"C_Sign": 7, "C_Verify": 5})
        + "\n"
        + _coverage_line({"C_Sign": 2}, {"C_Sign": 4})
        + "\n",
        encoding="utf-8",
    )

    merged = extract_coverage_from_jsonl(p)

    assert merged is not None
    fc = merged["function_coverage"]
    assert "ok_counts" in fc, "merge dropped ok_counts -> oracle numerator is always empty"
    # summed across the two per-file CoverageReport lines
    assert fc["ok_counts"] == {"C_Sign": 5, "C_Verify": 5}
    # existing called_counts behaviour is unchanged (C_Verify only in the first line)
    assert fc["called_counts"] == {"C_Sign": 11, "C_Verify": 5}
