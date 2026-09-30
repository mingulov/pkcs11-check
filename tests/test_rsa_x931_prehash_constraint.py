"""P11C-011: CKM_RSA_X9_31 registry entry must declare the prehash constraint.

X9.31 signs a pre-hashed digest, like PSS. Without input_constraint="prehash"
the registry-driven sign legs feed full-length messages and mis-score
providers. Only test_mech_sign.py consumes "prehash" (roundtrip + tampered
legs); rsa_extended and the registry guard are unaffected.
"""

from __future__ import annotations

from pkcs11_check.raw.types_std import CKM_RSA_X9_31
from pkcs11_check.testcases.mechanism_registry import MechConfig, get_config


def test_rsa_x9_31_declares_prehash_constraint() -> None:
    config = get_config(CKM_RSA_X9_31)
    assert config is not None, "no registry config for CKM_RSA_X9_31"
    assert config.input_constraint == "prehash", (
        f"CKM_RSA_X9_31 input_constraint is {config.input_constraint!r}, expected 'prehash'"
    )


def test_mechconfig_docstring_lists_prehash_and_raw_block() -> None:
    doc = MechConfig.__doc__ or ""
    assert "prehash" in doc, "MechConfig docstring omits the prehash constraint value"
    assert "raw_block" in doc, "MechConfig docstring omits the raw_block constraint value"
