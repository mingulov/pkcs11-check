"""Source-level guardrails for parameterized hybrid wrap coverage."""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RSA_EXTENDED = REPO / "src" / "pkcs11_check" / "testcases" / "test_rsa_extended.py"
AUTH_WRAP = REPO / "src" / "pkcs11_check" / "testcases" / "test_authenticated_wrap.py"


def _class_source(path: Path, class_name: str) -> str:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            segment = ast.get_source_segment(source, node)
            assert segment is not None
            return segment
    raise AssertionError(f"{path}: class {class_name} not found")


def test_rsa_aes_key_wrap_has_observed_tamper_classifier() -> None:
    """RSA-AES hybrid wrap must reject mutated wrapped blobs, not only roundtrip."""
    cls = _class_source(RSA_EXTENDED, "TestRSAAESKeyWrap")

    assert "tamper" in cls.lower() or "bit_flip" in cls.lower()
    assert "classify_discrimination(" in cls
    assert "CKM_RSA_AES_KEY_WRAP" in cls


def test_ecdh_aes_key_wrap_covers_oasis_family() -> None:
    """CK_ECDH_AES_KEY_WRAP_PARAMS applies to deprecated, cofactor, and X mechanisms."""
    source = AUTH_WRAP.read_text(encoding="utf-8")
    cls = _class_source(AUTH_WRAP, "TestEcdhAesKeyWrap")

    assert "_ECDH_AES_KW_CASES" in cls
    for mechanism in (
        "CKM_ECDH_AES_KEY_WRAP",
        "CKM_ECDH_COF_AES_KEY_WRAP",
        "CKM_ECDH_X_AES_KEY_WRAP",
    ):
        assert mechanism in source


def test_ecdh_aes_key_wrap_advertised_runtime_rejections_are_xfail_not_skip() -> None:
    """A clean rejection after has_mechanism() is advertised-but-not-operational evidence."""
    cls = _class_source(AUTH_WRAP, "TestEcdhAesKeyWrap")

    assert "Module rejected ECDH-AES-KW params" not in cls
    assert 'pytest.skip(f"Module rejected' not in cls
