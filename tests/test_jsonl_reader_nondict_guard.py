"""Regression tests for non-dict JSONL line robustness (review finding R4).

The streaming readers ``extract_coverage_from_jsonl``,
``postprocess_jsonl_to_unified`` and ``_identify_crash_culprit`` catch
``JSONDecodeError`` but then call ``rec.get(...)``. A line that is valid JSON but
not an object (a bare scalar: ``5``, ``"x"``, ``true``, ``[]``) parses fine and
would ``AttributeError`` — on the crash/final-report paths that aborts report
writing and loses the whole run's findings. These readers must skip non-dict
records like their siblings do.
"""

from __future__ import annotations

import json
from pathlib import Path

from pkcs11_check.core.file_runner import (
    _identify_crash_culprit,
    extract_coverage_from_jsonl,
    postprocess_jsonl_to_unified,
)

# A scalar, an array, and an object line interleaved (e.g. a crash-truncated or
# concatenated shard JSONL).
_SCALAR_NOISE = ["5", '"stray"', "true", "[1, 2, 3]"]


def _write(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n")


def test_extract_coverage_skips_non_dict_lines(tmp_path: Path) -> None:
    jsonl = tmp_path / "report.jsonl"
    coverage_rec = json.dumps(
        {
            "$report_type": "CoverageReport",
            "function_coverage": {"available": 10, "called_names": ["C_Initialize"]},
            "mechanism_coverage": {"available_names": ["CKM_AES_CBC"], "invoked_names": []},
        }
    )
    _write(jsonl, [*_SCALAR_NOISE, coverage_rec])

    coverage = extract_coverage_from_jsonl(jsonl)

    assert coverage is not None
    assert coverage["function_coverage"]["available"] == 10


def test_postprocess_unified_skips_non_dict_lines(tmp_path: Path) -> None:
    jsonl = tmp_path / "report.jsonl"
    call_rec = json.dumps(
        {
            "$report_type": "TestReport",
            "nodeid": "test_x.py::test_a",
            "when": "call",
            "outcome": "failed",
            "duration": 0.01,
        }
    )
    _write(jsonl, [*_SCALAR_NOISE, call_rec])

    payload = postprocess_jsonl_to_unified(jsonl, tmp_path / "results.json")

    assert payload is not None
    assert payload["summary"]["failed"] == 1


def test_identify_crash_culprit_skips_non_dict_lines(tmp_path: Path) -> None:
    jsonl = tmp_path / "report.jsonl"
    # setup started but no teardown -> this nodeid is the culprit.
    setup_rec = json.dumps(
        {
            "$report_type": "TestReport",
            "nodeid": "test_x.py::test_boom",
            "when": "setup",
            "outcome": "passed",
        }
    )
    _write(jsonl, [*_SCALAR_NOISE, setup_rec])

    culprit, _completed = _identify_crash_culprit(jsonl)

    assert culprit == "test_x.py::test_boom"
