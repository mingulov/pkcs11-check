"""Coverage tests: the renderer must SURFACE every enriched field it is given.

Each test feeds one finding shape and asserts the rendered .md actually shows the
information (a guard against 'computed but never rendered' regressions).
"""

from __future__ import annotations

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
