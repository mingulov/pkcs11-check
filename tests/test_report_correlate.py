"""Tests for tools.report.correlate — cross-provider themes + enrichment."""

from __future__ import annotations

from typing import Any

from tools.report.correlate import correlate, enrich


def _group(**over: Any) -> dict[str, Any]:
    grp: dict[str, Any] = {
        "test_file": "tests/test_x.py",
        "reason": "accepted_invalid",
        "outcome": "fail",
        "severity": "CRITICAL",
        "kind": "crypto",
        "operation": "C_Verify",
        "mechanism": "CKM_ECDSA_SHA256",
        "expected_ckr": ["CKR_SIGNATURE_INVALID"],
        "actual_ckr": "CKR_OK",
        "spec_ref": "PKCS#11 v3.2",
        "summary": "ECDSA accepts invalid signature",
        "count": 5,
        "nodeids": [],
        "vector_ids": [],
        "sources": ["acvp"],
    }
    grp.update(over)
    return grp


def test_universal_theme_across_three_providers() -> None:
    pg = {
        "softhsm2": [_group()],
        "kryoptic": [_group()],
        "nss": [_group()],
    }
    result = correlate(pg)
    themes = result["universal_themes"]
    assert len(themes) == 1
    theme = themes[0]
    assert theme["providers"] == 3
    assert theme["reason"] == "accepted_invalid"
    assert theme["kind"] == "crypto"
    assert theme["mechanism"] == "CKM_ECDSA_SHA256"


def test_single_provider_outlier() -> None:
    pg = {
        "softhsm2": [_group(mechanism="CKM_RSA_PKCS")],
        "kryoptic": [_group(mechanism="CKM_AES_GCM")],
    }
    result = correlate(pg)
    assert result["universal_themes"] == []
    outliers = result["outliers"]
    assert len(outliers) == 2


def test_enrich_default_fail_routing() -> None:
    groups = [_group()]
    enrich(groups, module_issues_text="", provider="softhsm2")
    g = groups[0]
    assert g["category"] == "PROVIDER_BUG"
    assert g["routing"] == "PROVIDER_REPORT"


def test_enrich_known_issue_match() -> None:
    groups = [_group(mechanism="CKM_ECDSA_SHA256", operation="C_Verify")]
    snippet = (
        "## SoftHSM2\n"
        "- ECDSA_SHA* accepts invalid signatures (ACVP SigVer): C_Verify with "
        "CKM_ECDSA_SHA256 accepts invalid vectors.\n"
    )
    enrich(groups, module_issues_text=snippet, provider="softhsm2")
    assert groups[0]["category"] == "KNOWN_ISSUE"
    # known issues route to docs, not a fresh provider report
    assert groups[0]["routing"] == "DOCS_ONLY"


def test_enrich_xfail_is_deviation() -> None:
    groups = [
        _group(
            reason="not_operational",
            outcome="xfail",
            severity="LOW",
            kind=None,
        )
    ]
    enrich(groups, module_issues_text="", provider="p")
    assert groups[0]["category"] == "deviation"


def test_enrich_unclassified_routes_to_harness() -> None:
    groups = [
        _group(
            reason="unclassified",
            outcome="fail",
            severity="HIGH",
            kind=None,
        )
    ]
    enrich(groups, module_issues_text="", provider="p")
    assert groups[0]["category"] == "HARNESS_OR_UNMIGRATED"
    assert groups[0]["routing"] == "HARNESS_FIX"


def test_enrich_soft_token_caveat_for_oracle() -> None:
    groups = [_group(reason="oracle", kind="crypto", severity="HIGH")]
    enrich(groups, module_issues_text="", provider="p")
    assert groups[0].get("soft_token_caveat") is True
