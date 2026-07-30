"""Coverage tests: the renderer must SURFACE every enriched field it is given.

Each test feeds one finding shape and asserts the rendered .md actually shows the
information (a guard against 'computed but never rendered' regressions).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pkcs11_check.report.render import render_provider


def _group(**over: Any) -> dict[str, Any]:
    grp: dict[str, Any] = {
        "test_file": "tests/test_x.py",
        "reason": "accepted_invalid",
        "outcome": "fail",
        "severity": "CRITICAL",
        "kind": "crypto",
        "operation": "C_Decrypt",
        "mechanism": "CKM_RSA_PKCS",
        "expected_ckr": ["CKR_ENCRYPTED_DATA_INVALID"],
        "actual_ckr": "CKR_OK",
        "spec_ref": "PKCS#11 v3.2",
        "summary": "RSA decrypt accepted forged ciphertext",
        "count": 1,
        "nodeids": ["tests/test_x.py::t1"],
        "vector_ids": ["tc1"],
        "sources": ["wycheproof"],
    }
    grp.update(over)
    return grp


def test_in_range_contradiction_is_surfaced() -> None:
    """A not_operational group tagged capability_verdict=IN_RANGE (T2) must appear
    in the capability section as an advertised-then-refused contradiction count."""
    g = _group(
        reason="not_operational",
        outcome="xfail",
        severity="INFO",
        kind=None,
        mechanism="CKM_ECDSA",
        operation="C_Sign",
        expected_ckr=None,
        actual_ckr="CKR_FUNCTION_NOT_SUPPORTED",
        summary="ECDSA advertised IN_RANGE but not operational",
        count=3,
        detail={"capability_verdict": "IN_RANGE", "key_size": 256},
    )
    out = render_provider("p", [g])
    assert "contradiction" in out.lower(), "IN_RANGE contradiction count not surfaced"
    # the count and the offending mechanism are shown
    line = next(ln for ln in out.splitlines() if "contradiction" in ln.lower())
    assert "3" in line
    assert "CKM_ECDSA" in out


def test_crash_signal_surfaced_and_target_not_duplicated() -> None:
    """A crash group's detail.signal must appear; the target must not be printed twice."""
    g = _group(
        reason="crash",
        outcome="fail",
        severity="HIGH",
        kind=None,
        operation=None,
        mechanism=None,
        expected_ckr=None,
        actual_ckr=None,
        test_file="tests/security/test_overflow.py",
        summary="tests/security/test_overflow.py: process crashed",
        detail={"signal": "SIGSEGV", "returncode": -11},
        count=1,
    )
    out = render_provider("p", [g])
    crash_line = next(
        ln for ln in out.splitlines() if ln.startswith("[1]") and "test_overflow" in ln
    )
    assert "SIGSEGV" in crash_line, f"signal not surfaced: {crash_line}"
    # the target path must appear exactly once on the line (no '...py - ...py:' duplication)
    assert crash_line.count("test_overflow.py") == 1, f"target duplicated: {crash_line}"


def test_data_quality_warnings_surfaced() -> None:
    """quality.json data_quality_warnings (the report's own inputs were incomplete)
    must be surfaced, not silently dropped (which would overstate completeness)."""
    quality = {
        "data_quality_warnings": [
            "results.json unit lacks explicit test details; using aggregated skip_reasons only",
        ],
        "framework_skip_candidates": [],
    }
    out = render_provider("p", [_group()], quality=quality)
    assert "lacks explicit test details" in out, "data_quality_warnings not surfaced"
    assert "data quality" in out.lower() or "caveat" in out.lower()


def test_uncategorized_severity_fail_is_not_dropped() -> None:
    """A scored fail whose severity is outside the four known sections must still
    render. Otherwise the header counts it (outcome_counts) while the section loop
    skips it - a silent finding drop, the exact failure this project forbids."""
    g = _group(severity="INFO", reason="wrong_result", summary="oddball-severity fail")
    out = render_provider("p", [g])
    assert "oddball-severity fail" in out, "fail with an unknown severity was dropped"
    assert "fail" in out.lower()


def test_reproducer_handles_rendered_on_fail() -> None:
    """vector_ids/sources are computed by extract but were never rendered; the
    reproducer handle (vector file + case id) must surface, not hide in the .jsonl."""
    g = _group(
        vector_ids=["tc82-valid", "tc83-valid", "+40"],
        sources=["hmac_sha1_test.json"],
    )
    out = render_provider("p", [g])
    assert "hmac_sha1_test.json" in out, "source vector file not surfaced"
    assert "tc82-valid" in out, "vector_id reproducer not surfaced"


def test_invoked_mechanism_params_surfaced() -> None:
    """coverage.invoked_detail (rich per-mechanism params, e.g. CKM_AES_GCM[tagBits=0])
    is computed but was never rendered; surface the param variants that were exercised."""
    coverage = {
        "mechanism_coverage": {
            "invoked_detail": [
                "CKM_AES_GCM[tagBits=0]",
                "CKM_AES_GCM[tagBits=128]",
                "CKM_AES_CTR[counterBits=129]",
                "CKM_RSA_PKCS",  # bare, no params - not param-detail
            ]
        }
    }
    out = render_provider("p", [_group()], coverage=coverage)
    assert "mechanism param" in out.lower(), "invoked mechanism params not surfaced"
    # grouped per mechanism, values collapsed per param key: CKM_AES_GCM[tagBits=0,128]
    gcm = next(line for line in out.splitlines() if "CKM_AES_GCM" in line and "tagBits" in line)
    assert "0" in gcm and "128" in gcm, gcm
    assert "CKM_AES_CTR" in out and "129" in out


def test_invoked_mechanism_params_absent_is_silent() -> None:
    out = render_provider("p", [_group()], coverage={"mechanism_coverage": {"invoked_detail": []}})
    assert "mechanism param" not in out.lower()


def test_report_has_automated_check_caveat() -> None:
    """The report must caveat that it is an automated check: it can miss real issues
    AND over-report, and large fail/xfail counts are usually one behavior repeated
    across many vectors, not that many distinct defects. Asks the reader to verify."""
    out = render_provider("p", [_group()])
    low = out.lower()
    assert "automated" in low
    assert "false positive" in low or "over-report" in low or "incorrect" in low
    assert "miss" in low or "false negative" in low
    # the count-amplification trap (a large count = one behavior x many test vectors)
    assert "vector" in low and ("distinct" in low or "repeat" in low)
    assert "verify" in low or "confirm" in low


def test_report_header_shows_provenance() -> None:
    """Provenance from results.json must appear in the report header."""
    prov = {
        "framework": {"version": "v0.1.6-42-gc539616"},
        "provider": {
            "name": "softhsm2",
            "ref": "2.7.0",
            "commit": "8d4f1a2cdead",
            "matches_manifest_pin": True,
        },
        "test_data": [{"name": "wycheproof", "commit": "ee7b4f7e"}],
    }
    out = render_provider("softhsm2", [_group()], provenance=prov)
    assert "tested: softhsm2 2.7.0@8d4f1a2c" in out
    assert "by pkcs11-check v0.1.6-42-gc539616" in out
    assert "matches pin" in out
    assert "wycheproof@ee7b4f7e" in out


def test_report_header_provenance_absent_is_silent() -> None:
    """When provenance is not provided the report must not emit a 'tested:' line."""
    out = render_provider("softhsm2", [_group()])
    assert "tested:" not in out


def test_end_to_end_kitchensink_surfaces_all_signals(tmp_path: Path) -> None:
    """Drive the full generator (extract -> enrich -> render) over one rich dataset
    spanning every signal, and assert each surfaces in the produced .md."""
    import json

    from pkcs11_check.report.__main__ import main

    def cls(**kw: Any) -> dict[str, Any]:
        base = {"reason": "", "outcome": "", "severity": "", "schema": 1}
        base.update(kw)
        return base

    def tr(nodeid: str, recs: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "$report_type": "TestReport",
            "when": "call",
            "nodeid": nodeid,
            "outcome": "failed",
            "user_properties": [["pkcs11_classification", recs]],
        }

    records = [
        # crypto break + oracle (soft-token caveat) + a curve param needing normalize
        tr(
            "t/test_ecdsa.py::a",
            [
                cls(
                    reason="accepted_invalid",
                    outcome="fail",
                    severity="CRITICAL",
                    kind="crypto",
                    mechanism="CKM_ECDSA",
                    operation="C_Verify",
                    summary="forged sig accepted",
                    params={"curve": "P-256"},
                )
            ],
        ),
        tr(
            "t/test_ecdsa.py::b",
            [
                cls(
                    reason="accepted_invalid",
                    outcome="fail",
                    severity="CRITICAL",
                    kind="crypto",
                    mechanism="CKM_ECDSA",
                    operation="C_Verify",
                    summary="forged sig accepted",
                    params={"curve": "secp256r1"},
                )
            ],
        ),
        tr(
            "t/test_oracle.py::c",
            [
                cls(
                    reason="oracle",
                    outcome="fail",
                    severity="HIGH",
                    kind="crypto",
                    mechanism="CKM_RSA_PKCS",
                    operation="C_Decrypt",
                    summary="padding oracle",
                )
            ],
        ),
        # IN_RANGE contradiction (T2)
        tr(
            "t/test_cap.py::d",
            [
                cls(
                    reason="not_operational",
                    outcome="xfail",
                    severity="INFO",
                    mechanism="CKM_ECDSA",
                    operation="C_Sign",
                    actual_ckr="CKR_FUNCTION_NOT_SUPPORTED",
                    summary="advertised in-range but refused",
                    detail={"capability_verdict": "IN_RANGE", "key_size": 256},
                )
            ],
        ),
    ]
    report = tmp_path / "report.jsonl"
    report.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    results = tmp_path / "results.json"
    results.write_text(
        json.dumps(
            {
                "summary": {
                    "passed": 900,
                    "total": 1000,
                    "failed": 3,
                    "crashed": 1,
                    "timeout": 0,
                    "crash_limited": 0,
                    "incomplete": False,
                },
                "coverage": {
                    "mechanism_coverage": {
                        "advertised_names": ["CKM_ECDSA", "CKM_RSA_PKCS"],
                        "invoked": 2,
                        "accepted_names": ["CKM_RSA_PKCS"],
                        "rejected_cleanly_names": ["CKM_ECDSA"],
                    }
                },
                "units": [
                    {
                        "target": "t/security/test_crash.py",
                        "status": "crashed",
                        "returncode": 11,
                        "duration_s": 1.0,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    quality = tmp_path / "quality.json"
    quality.write_text(
        json.dumps(
            {
                "data_quality_warnings": ["coverage.json not provided; counts approximate"],
                "framework_skip_candidates": [
                    {
                        "reason": "AES_CCM not supported by module",
                        "category": "missing_capability",
                        "count": 4200,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    rc = main(
        [
            "--report-log",
            str(report),
            "--results-json",
            str(results),
            "--provider",
            "demo",
            "--out",
            str(tmp_path / "out"),
        ]
    )
    assert rc == 0
    md = (tmp_path / "out" / "demo.md").read_text(encoding="utf-8")

    # health + coverage
    assert "passed 900/1000 (90%)" in md
    assert "advertised 2 -> invoked 2 -> accepted 1 (rejected 1)" in md
    # crypto break, oracle + soft-token caveat
    assert "forged sig accepted" in md
    assert "(soft-token caveat)" in md
    # curve breakdown, normalized: P-256 and secp256r1 collapse to ONE bucket of 2
    assert "curve=secp256r1 (2)" in md
    assert "P-256" not in md
    # T2 IN_RANGE contradiction
    assert "contradiction" in md.lower()
    # crash with signal, capability gaps, data-quality caveat
    assert "SIGSEGV" in md
    # skip_reasons normalizes the phrasing to a per-mechanism "<mech> not supported"
    assert "AES_CCM not supported (x4200)" in md
    assert "data quality caveat: coverage.json not provided" in md
