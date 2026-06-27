"""Tests for tools.report.render — compact enriched provider markdown."""

from __future__ import annotations

from typing import Any

from tools.report.render import render_provider


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
    )
    out = render_provider("softhsm2", [crit, xfail], pass_count=44957)

    lines = out.splitlines()
    assert len(lines) < 60, f"too many lines: {len(lines)}"

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
    # the count line carries the reason
    assert "not_operational" in collapsed[0]

    # NO sha1 anywhere
    assert "sha1" not in out.lower()


def test_counts_line_and_pass_omitted_when_none() -> None:
    crit = _group()
    out = render_provider("kryoptic", [crit])
    header = out.splitlines()[0]
    assert header.startswith("# kryoptic")
    # pass omitted when pass_count is None
    counts_line = out.splitlines()[1]
    assert "passed" not in counts_line
    assert "fail 1" in counts_line


def test_kind_keywords_no_type_aliases() -> None:
    groups = [
        _group(kind="crypto", reason="wrong_result", severity="CRITICAL"),
        _group(kind="policy", reason="self_contradiction", severity="CRITICAL"),
        _group(kind="lifecycle", reason="self_contradiction", severity="HIGH"),
        _group(kind="metadata", reason="self_contradiction", severity="HIGH"),
    ]
    out = render_provider("p", groups)
    # kind · reason keywords are present
    assert "crypto · wrong_result" in out
    assert "policy · self_contradiction" in out
    assert "lifecycle · self_contradiction" in out
    assert "metadata · self_contradiction" in out
    # no Type-letter aliases anywhere
    assert "(Type A)" not in out
    assert "(Type B)" not in out
    assert "(Type C)" not in out
    assert "(Type D)" not in out


def test_unclassified_collapsed_to_single_line() -> None:
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
    unc_lines = [ln for ln in out.splitlines() if "unclassified" in ln.lower()]
    # exactly one count line mentioning unclassified + the count
    count_lines = [ln for ln in unc_lines if "37" in ln]
    assert len(count_lines) == 1


def test_crash_limited_in_counts_line_and_incomplete_banner() -> None:
    text = render_provider("demo", groups=[], pass_count=10, crash_limited=7, incomplete=True)
    assert "crash_limited 7" in text
    assert "INCOMPLETE COVERAGE" in text


def test_no_crash_limited_token_when_zero() -> None:
    text = render_provider("demo", groups=[], pass_count=10, crash_limited=0, incomplete=False)
    assert "crash_limited" not in text
    assert "INCOMPLETE COVERAGE" not in text


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

    # the xfail section header must be present
    assert "deviations" in out

    # the count line for undeclared_capability must appear with the count
    reason_lines = [ln for ln in out.splitlines() if "undeclared_capability" in ln]
    assert reason_lines, "undeclared_capability not found in rendered output"
    count_lines = [ln for ln in reason_lines if "15" in ln]
    assert count_lines, "undeclared_capability count line with [15] not found"
