"""Guardrails for registry-driven mechanism-negative coverage."""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MECH_NEGATIVE = REPO / "src" / "pkcs11_check" / "testcases" / "test_mech_negative.py"


def _source() -> str:
    return MECH_NEGATIVE.read_text()


def _fixture_names() -> set[str]:
    tree = ast.parse(_source())
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for arg in node.args.args:
            names.add(arg.arg)
    return names


def test_negative_tests_use_registry_operation_fixtures() -> None:
    """Negative coverage must scale beyond the fixed explicit examples."""
    fixtures = _fixture_names()

    for fixture in (
        "mech_encrypt_entry",
        "mech_sign_entry",
        "mech_digest_entry",
        "mech_wrap_entry",
        "mech_derive_entry",
    ):
        assert fixture in fixtures


def test_permission_negatives_use_three_way_classification() -> None:
    """Accepted forbidden ops fail; non-spec clean rejects xfail rather than disappearing."""
    source = _source()

    assert "classify_negative_rv(" in source
    assert "classify_policy_enforcement(" in source


def test_wrong_key_negatives_are_registry_driven() -> None:
    """Wrong-key-type negatives should not be limited to named smoke examples."""
    source = _source()

    assert "test_registry_encrypt_wrong_key_type" in source
    assert "test_registry_decrypt_wrong_key_type" in source
    assert "test_registry_sign_wrong_key_type" in source
    assert "test_registry_verify_wrong_key_type" in source


def test_permission_negatives_cover_roundtrip_pairs() -> None:
    """Permission negatives should exercise both halves of selected operation pairs."""
    source = _source()

    for test_name in (
        "test_registry_encrypt_without_flag",
        "test_registry_decrypt_without_flag",
        "test_registry_sign_without_flag",
        "test_registry_verify_without_flag",
        "test_registry_wrap_without_flag",
        "test_registry_unwrap_without_flag",
        "test_registry_derive_without_flag",
    ):
        assert test_name in source


def test_unwrap_shape_negatives_are_registry_driven() -> None:
    """Malformed wrapped-blob negatives should scale with wrap registry entries."""
    source = _source()

    assert "test_registry_unwrap_rejects_truncated_blob" in source
    assert "_MALFORMED_WRAPPED_BLOB_RVS" in source


def test_bad_param_negatives_are_registry_driven() -> None:
    """Bad-parameter coverage should not be limited to fixed named mechanisms."""
    source = _source()

    assert "test_registry_encrypt_missing_required_param" in source
    assert "test_registry_encrypt_malformed_required_param" in source
    assert "test_registry_decrypt_missing_required_param" in source
    assert "test_registry_decrypt_malformed_required_param" in source
    assert "test_registry_sign_missing_required_param" in source
    assert "test_registry_sign_malformed_required_param" in source
    assert "test_registry_verify_missing_required_param" in source
    assert "test_registry_verify_malformed_required_param" in source
    assert "test_registry_digest_missing_required_param" in source
    assert "test_registry_digest_malformed_required_param" in source
    assert "test_registry_derive_malformed_required_param" in source
