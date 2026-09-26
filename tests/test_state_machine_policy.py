"""Regression checks for state-machine CKR policy."""

from __future__ import annotations

import ast
from pathlib import Path

from pkcs11_check.raw.types_std import CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE


def test_verify_state_uses_named_signature_ckrs() -> None:
    """Verify state tests must use generated CKR constants, not stale magic values."""
    source = Path("src/pkcs11_check/testcases/test_mech_state.py").read_text(encoding="utf-8")

    assert "CKR_SIGNATURE_INVALID" in source
    assert "CKR_SIGNATURE_LEN_RANGE" in source
    assert "0x000000C4" not in source
    assert "0x000000C5" not in source


def test_signature_ckr_values_match_pkcs11_constants() -> None:
    """Guard against the previous off-by-four stale constants in verify-state checks."""
    assert int(CKR_SIGNATURE_INVALID) == 0x000000C0
    assert int(CKR_SIGNATURE_LEN_RANGE) == 0x000000C1


def test_zero_data_final_has_no_stale_buffer_too_small_literal() -> None:
    """0x63 is CKR_KEY_TYPE_INCONSISTENT, never a CKR_BUFFER_TOO_SMALL oracle.

    The zero-data EncryptFinal path once accepted the ``0x63`` literal as
    "CKR_BUFFER_TOO_SMALL on length-query" (the real value is 0x150). Raw
    ``0x63`` integer literals and the stale length-query comment must stay out
    of the mechanism-state probes; rejections use symbolic constants and the
    shared defined/vendor classifier. (Docstrings may still name the value to
    document the mapping, so the literal check is AST-based, not textual.)
    """
    source = Path("src/pkcs11_check/testcases/test_mech_state.py").read_text(encoding="utf-8")
    module = ast.parse(source)
    stale = [
        node for node in ast.walk(module) if isinstance(node, ast.Constant) and node.value == 0x63
    ]
    assert stale == [], "stale 0x63 literal in test_mech_state.py: use symbolic CKR constants"
    assert "length-query" not in source, "stale length-query premise still present"


def test_no_active_operation_forbids_allow_ok() -> None:
    """C_GetOperationState with no active operation must not tolerate CKR_OK.

    Statically forbids ``allow_ok=True`` in the no-active-operation probe: with
    nothing to save, CKR_OK is accepted-invalid FAIL via the shared negative
    classifier, and only CKR_OPERATION_NOT_INITIALIZED passes.
    """
    source = Path("src/pkcs11_check/testcases/test_operation_state.py").read_text(encoding="utf-8")
    module = ast.parse(source)
    (method,) = [
        node
        for node in ast.walk(module)
        if isinstance(node, ast.FunctionDef) and node.name == "test_no_active_operation"
    ]
    allow_ok_uses = [
        node
        for node in ast.walk(method)
        if isinstance(node, ast.keyword) and node.arg == "allow_ok"
    ]
    assert allow_ok_uses == [], "allow_ok=True must not appear in test_no_active_operation"
