"""fw#43: CKM_RSA_X9_31 registry entry must declare the x931 constraint.

X9.31 signs digest || trailer-ID (the application applies the trailer; a
bare digest is invalid input). The legs therefore need a dedicated
input_constraint -- "prehash" was tried and reverted (0d1fcac2) because it
feeds trailer-less digests. Only test_mech_sign.py consumes "x931"
(roundtrip + mismatch legs).
"""

from __future__ import annotations

from pkcs11_check.raw.types_std import CKM_RSA_X9_31
from pkcs11_check.testcases.mechanism_registry import MechConfig, get_config


def test_rsa_x9_31_declares_x931_constraint() -> None:
    config = get_config(CKM_RSA_X9_31)
    assert config is not None, "no registry config for CKM_RSA_X9_31"
    assert config.input_constraint == "x931", (
        f"CKM_RSA_X9_31 input_constraint is {config.input_constraint!r}, expected 'x931'"
    )


def test_mechconfig_docstring_lists_x931() -> None:
    doc = MechConfig.__doc__ or ""
    assert "x931" in doc, "MechConfig docstring omits the x931 constraint value"
