"""Regression checks for state-machine CKR policy."""

from __future__ import annotations

from pathlib import Path

from pkcs11_check.raw.types_std import CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE


def test_verify_state_uses_named_signature_ckrs() -> None:
    """Verify state tests must use generated CKR constants, not stale magic values."""
    source = Path("src/pkcs11_check/testcases/test_mech_state.py").read_text()

    assert "CKR_SIGNATURE_INVALID" in source
    assert "CKR_SIGNATURE_LEN_RANGE" in source
    assert "0x000000C4" not in source
    assert "0x000000C5" not in source


def test_signature_ckr_values_match_pkcs11_constants() -> None:
    """Guard against the previous off-by-four stale constants in verify-state checks."""
    assert int(CKR_SIGNATURE_INVALID) == 0x000000C0
    assert int(CKR_SIGNATURE_LEN_RANGE) == 0x000000C1
