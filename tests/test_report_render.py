"""Tests for pkcs11_check.report.render - health-first noise-reduced provider markdown."""

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


def test_critical_before_deviations_and_xfail_collapsed() -> None:
    crit = _group()
    xfail = _group(
        reason="not_operational",
        outcome="xfail",
        severity="LOW",
        kind=None,
        mechanism="CKM_AES_GCM",
        operation="C_Encrypt",
        expected_ckr=None,
        actual_ckr="CKR_FUNCTION_FAILED",
        summary="AES-GCM advertised but not operational",
        count=24000,
        vector_ids=["v1", "v2", "+100"],
        routing="CAPABILITY_AUDIT",
    )
    out = render_provider("softhsm2", [crit, xfail], summary={"passed": 44957, "total": 120000})

    lines = out.splitlines()
    assert len(lines) < 70, f"too many lines: {len(lines)}"

    # CRITICAL section appears before deviations
    crit_idx = next(i for i, ln in enumerate(lines) if "CRITICAL" in ln)
    dev_idx = next(i for i, ln in enumerate(lines) if "deviations" in ln)
    assert crit_idx < dev_idx

    # exact values present
    assert "CKR_OK" in out
    assert "CKM_RSA_PKCS" in out
    assert "PKCS#11 v3.2" in out

    # kind keyword present, no Type-letter alias
    assert "crypto · accepted_invalid" in out
    assert "(Type A)" not in out

    # the 24000 xfail is a SINGLE collapsed finding line, not enumerated
    collapsed = [ln for ln in lines if ln.startswith("[24000]")]
    assert len(collapsed) == 1
    assert "not_operational" in collapsed[0]
    # its per-reason routing is surfaced
    assert "CAPABILITY_AUDIT" in collapsed[0]

    # NO sha1 anywhere
    assert "sha1" not in out.lower()


def test_health_line_shows_pass_and_fail() -> None:
    out = render_provider("kryoptic", [_group()], summary={"passed": 100, "total": 200})
    health = next(ln for ln in out.splitlines() if ln.startswith("passed "))
    assert health.startswith("passed 100/200 (50%)")
    assert "fail 1 (CRITICAL 1" in health


def test_header_is_real_markdown_heading() -> None:
    out = render_provider("p", [_group()])
    assert out.splitlines()[0] == "# p - conformance report"
    # severity sections are real markdown headings, not box-drawing
    assert "## CRITICAL - fail" in out
    assert "━" not in out  # no heavy box-drawing dashes


def test_threat_model_note_present_without_quantifier() -> None:
    out = render_provider("p", [_group()])
    assert "## before you report" in out
    assert "in-process" in out
    assert "hardening opportunity" in out
    # no proportion claim about findings
    assert "most findings" not in out.lower()


def test_kind_keywords_no_type_aliases() -> None:
    groups = [
        _group(kind="crypto", reason="wrong_result", severity="CRITICAL"),
        _group(kind="policy", reason="self_contradiction", severity="CRITICAL"),
        _group(kind="lifecycle", reason="self_contradiction", severity="HIGH"),
        _group(kind="metadata", reason="self_contradiction", severity="HIGH"),
    ]
    out = render_provider("p", groups)
    assert "crypto · wrong_result" in out
    assert "policy · self_contradiction" in out
    assert "lifecycle · self_contradiction" in out
    assert "metadata · self_contradiction" in out
    for letter in ("A", "B", "C", "D"):
        assert f"(Type {letter})" not in out


def test_unclassified_in_appendix_not_enumerated() -> None:
    unc = _group(
        reason="unclassified",
        outcome="fail",
        severity="HIGH",
        kind=None,
        mechanism=None,
        operation=None,
        expected_ckr=None,
        actual_ckr=None,
        summary="raw pytest.fail",
        count=37,
    )
    out = render_provider("p", [unc])
    # the appendix carries a single backlog line, not 37 enumerated findings
    assert "unclassified backlog: 37" in out
    assert out.lower().count("raw pytest.fail") == 0


def test_incomplete_banner_from_summary_names_unit() -> None:
    summary = {"incomplete": True, "crash_limited": 7, "timeout": 0}
    units = [
        {
            "target": "x/test_hkdf.py",
            "status": "crashed",
            "duration_s": 30.0,
            "counts": {"crash_limited": 7},
        }
    ]
    out = render_provider("demo", [], summary=summary, units=units)
    assert "INCOMPLETE COVERAGE" in out
    assert "test_hkdf.py" in out


def test_no_incomplete_banner_when_complete() -> None:
    out = render_provider("demo", [], summary={"incomplete": False})
    assert "INCOMPLETE COVERAGE" not in out


def test_undeclared_capability_appears_in_xfail_breakdown() -> None:
    """undeclared_capability xfail must appear in the per-reason breakdown section."""
    xfail = _group(
        reason="undeclared_capability",
        outcome="xfail",
        severity="LOW",
        kind=None,
        operation="C_Sign",
        mechanism="CKM_ECDSA",
        expected_ckr=None,
        actual_ckr="CKR_FUNCTION_NOT_SUPPORTED",
        summary="mechanism advertised but capability not declared",
        count=15,
    )
    out = render_provider("p", [xfail])
    assert "deviations" in out
    reason_lines = [ln for ln in out.splitlines() if "undeclared_capability" in ln]
    assert reason_lines, "undeclared_capability not found in rendered output"
    assert any("15" in ln for ln in reason_lines), "undeclared_capability count line not found"
