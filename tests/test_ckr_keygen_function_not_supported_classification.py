"""Regression test for PC-6: tpm2 C_GenerateKey -> CKR_FUNCTION_NOT_SUPPORTED.

tpm2-pkcs11 has no symmetric-keygen surface, so a negative C_GenerateKey probe
(bad size / inconsistent / bogus-type template) returns CKR_FUNCTION_NOT_SUPPORTED
-- the whole function is unavailable. That is an honest missing-capability
deviation, so it must classify as **xfail** (noted, investigate later), not a
hard fail. A wrong-accept (CKR_OK) on a non-permissive probe must still fail.

See docs/findings/catalog.md PC-6 and docs/module-issues.md.
"""

from __future__ import annotations

import pytest
from _pytest.outcomes import Failed

from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED, CKR_OK
from pkcs11_check.testcases.ckr._ckr_spec import CKR_KEYGEN, assert_ckr

_FUNCTION_NOT_SUPPORTED_KEYS = (
    "genkey_bad_size",
    "genkey_template_inconsistent",
    "genkey_attribute_type_invalid",
)


@pytest.mark.parametrize("key", _FUNCTION_NOT_SUPPORTED_KEYS)
def test_keygen_function_not_supported_classifies_as_xfail(key: str) -> None:
    with pytest.raises(pytest.xfail.Exception):
        assert_ckr(CKR_KEYGEN[key], CKR_FUNCTION_NOT_SUPPORTED, strict=False)


def test_keygen_wrong_accept_still_fails() -> None:
    # genkey_template_inconsistent has no allow_success: accepting (CKR_OK) is a
    # Type-A wrong-accept and must remain a hard fail (never softened by PC-6).
    with pytest.raises(Failed):
        assert_ckr(CKR_KEYGEN["genkey_template_inconsistent"], CKR_OK, strict=False)
