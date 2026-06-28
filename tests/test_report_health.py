"""Tests for pkcs11_check.report.health - header health/coverage summary lines."""

from __future__ import annotations

from typing import Any

from pkcs11_check.report.health import (
    coverage_funnel,
    fail_severity_counts,
    health_lines,
    incomplete_banner,
    outcome_counts,
)


def _g(reason: str, outcome: str, severity: str, count: int) -> dict[str, Any]:
    return {"reason": reason, "outcome": outcome, "severity": severity, "count": count}


GROUPS = [
    _g("accepted_invalid", "fail", "CRITICAL", 2),
    _g("self_contradiction", "fail", "HIGH", 3),
    _g("crash", "fail", "HIGH", 7),
    _g("not_operational", "xfail", "INFO", 50),
    _g("unclassified", "fail", "HIGH", 11),
]


def test_fail_severity_counts_excludes_crash_and_unclassified() -> None:
    assert fail_severity_counts(GROUPS) == {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 0, "LOW": 0}


def test_outcome_counts_partitions_findings() -> None:
    assert outcome_counts(GROUPS) == {"fail": 5, "crash": 7, "xfail": 50, "unclassified": 11}


def test_health_first_line_content() -> None:
    lines = health_lines({"passed": 100, "total": 200}, None, GROUPS)
    assert len(lines) == 1
    line = lines[0]
    assert line.startswith("passed 100/200 (50%)")
    assert "fail 5 (CRITICAL 2" in line
    assert "HIGH 3)" in line
    assert "crash 7" in line
    assert "xfail 50" in line
    assert "unclassified 11 (not scored)" in line


def test_health_omits_unclassified_when_zero() -> None:
    groups = [_g("accepted_invalid", "fail", "CRITICAL", 1)]
    line = health_lines({"passed": 1, "total": 2}, None, groups)[0]
    assert "unclassified" not in line


def test_health_includes_error_when_nonzero() -> None:
    line = health_lines({"passed": 1, "total": 2, "error": 4}, None, [])[0]
    assert "error 4" in line


def test_health_zero_total_does_not_divide_by_zero() -> None:
    line = health_lines({"passed": 0, "total": 0}, None, [])[0]
    assert line.startswith("passed 0/0 (0%)")


def test_coverage_funnel_mechanism_and_function() -> None:
    cov = {
        "mechanism_coverage": {
            "advertised_names": ["A", "B", "C"],
            "invoked": 5,
            "accepted_names": ["A", "B"],
            "rejected_cleanly_names": ["C"],
        },
        "function_coverage": {"called": 60, "available": 68},
    }
    funnel = coverage_funnel(cov)
    assert funnel is not None
    assert "advertised 3" in funnel
    assert "invoked 5" in funnel
    assert "accepted 2" in funnel
    assert "rejected 1" in funnel
    assert "functions 60/68" in funnel


def test_coverage_funnel_invoked_clamped_to_advertised() -> None:
    # invoked_names may include mechanisms the harness probed that the module never
    # advertised (e.g. CKM_HASH_ML_DSA_* on the real softhsm2 round); the funnel is
    # "of advertised" so invoked must not exceed advertised (it read 88 > 84). The
    # undeclared-probed extras are surfaced separately, not folded in.
    cov = {
        "mechanism_coverage": {
            "advertised_names": ["A", "B", "C"],
            "invoked_names": ["A", "B", "X", "Y"],  # 2 advertised + 2 not advertised
            "accepted_names": ["A"],
            "rejected_cleanly_names": ["B"],
        }
    }
    funnel = coverage_funnel(cov)
    assert funnel is not None
    assert "advertised 3 -> invoked 2" in funnel, funnel  # 2, not 4 - monotonic
    assert "+2 invoked not advertised" in funnel, funnel


def test_coverage_funnel_none_when_absent() -> None:
    assert coverage_funnel(None) is None
    assert coverage_funnel({}) is None


def test_health_lines_appends_funnel() -> None:
    cov = {
        "mechanism_coverage": {
            "advertised_names": ["A"],
            "invoked": 1,
            "accepted_names": ["A"],
            "rejected_cleanly_names": [],
        }
    }
    lines = health_lines({"passed": 1, "total": 2}, cov, [])
    assert len(lines) == 2
    assert "advertised 1" in lines[1]


def test_incomplete_banner_none_when_complete() -> None:
    assert incomplete_banner({"incomplete": False}, []) is None


def test_incomplete_banner_names_abandoned_unit() -> None:
    summary = {"incomplete": True, "crash_limited": 62, "timeout": 2}
    units = [
        {
            "target": "/app/src/pkcs11_check/testcases/wycheproof/test_wycheproof_hkdf.py",
            "status": "timeout",
            "duration_s": 1017.3,
            "counts": {"crash_limited": 62, "timeout": 2},
        },
        {"target": "x/test_ok.py", "status": "passed", "counts": {}},
    ]
    banner = incomplete_banner(summary, units)
    assert banner is not None
    assert "INCOMPLETE" in banner
    assert "test_wycheproof_hkdf.py" in banner
    assert "62" in banner
    assert "1017s" in banner
