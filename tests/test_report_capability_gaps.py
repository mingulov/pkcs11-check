"""Tests for the capability-gap table (mechanism axis) in pkcs11_check.report.capability."""

from __future__ import annotations

from pkcs11_check.report.capability import (
    advertised_not_operational,
    render_capability_gaps,
    skip_reasons,
)

MC = {
    "advertised_names": ["CKM_AES_GCM", "CKM_RSA_PKCS", "CKM_AES_CMAC", "CKM_DSA"],
    "accepted_names": ["CKM_AES_GCM"],
    "rejected_cleanly_names": ["CKM_RSA_PKCS"],
    "crashed_names": ["CKM_DSA"],
    "timeout_names": [],
}


def test_advertised_not_operational_partitions() -> None:
    g = advertised_not_operational(MC)
    assert g["rejected_cleanly"] == ["CKM_RSA_PKCS"]
    assert g["crashed"] == ["CKM_DSA"]
    assert g["timeout"] == []
    assert g["limbo"] == ["CKM_AES_CMAC"]  # advertised, not accepted/rejected/crashed


def test_rejected_cleanly_excludes_also_accepted() -> None:
    # A mechanism that SUCCEEDED in one canonical scenario and was cleanly refused in
    # another is NOT a capability gap (it works). Listing CKM_RSA_PKCS under "rejected
    # a canonical op" reads as "RSA is broken" - false and alarming. Only a mechanism
    # rejected AND never accepted is a real advertised-but-doesn't-work gap.
    mc = {
        "advertised_names": ["CKM_RSA_PKCS", "CKM_AES_KEY_WRAP"],
        "accepted_names": ["CKM_RSA_PKCS"],
        "rejected_cleanly_names": ["CKM_RSA_PKCS", "CKM_AES_KEY_WRAP"],
    }
    g = advertised_not_operational(mc)
    assert g["rejected_cleanly"] == ["CKM_AES_KEY_WRAP"], g["rejected_cleanly"]


def test_advertised_not_operational_empty() -> None:
    assert advertised_not_operational(None) == {
        "rejected_cleanly": [],
        "crashed": [],
        "timeout": [],
        "limbo": [],
    }


def test_skip_reasons_top_missing_capability_only() -> None:
    fsc = [
        {"reason": "AES_CCM not supported", "category": "missing_capability", "count": 100},
        {"reason": "CS3 only", "category": "framework_constraint", "count": 999},
        {"reason": "AES_CTS not supported", "category": "missing_capability", "count": 200},
    ]
    top = skip_reasons(fsc, limit=10)
    assert [s["reason"] for s in top] == ["AES_CTS not supported", "AES_CCM not supported"]


def test_render_capability_gaps_content() -> None:
    out = render_capability_gaps(
        MC,
        [{"reason": "AES_CCM not supported", "category": "missing_capability", "count": 8398}],
    )
    assert "## capability gaps" in out
    assert "advertised but rejected a canonical op (1): CKM_RSA_PKCS" in out
    assert "advertised but CRASHED on probe (1): CKM_DSA" in out
    assert "no canonical accept/reject observed (1): CKM_AES_CMAC" in out
    assert "AES_CCM not supported (x8398)" in out


def test_render_capability_gaps_empty() -> None:
    out = render_capability_gaps({}, [])
    assert "no advertised-capability gaps observed" in out
