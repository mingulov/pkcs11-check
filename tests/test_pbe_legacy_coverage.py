"""Coverage guardrails for legacy PBE mechanism tests."""

from __future__ import annotations

from pkcs11_check.raw.types_std import (
    CKM_PBE_MD2_DES_CBC,
    CKM_PBE_MD5_DES_CBC,
    CKM_PBE_SHA1_RC2_40_CBC,
    CKM_PBE_SHA1_RC2_128_CBC,
    CKM_PBE_SHA1_RC4_40,
    CKM_PBE_SHA1_RC4_128,
)
from pkcs11_check.testcases import test_pbe


def test_legacy_pbe_case_table_covers_obsolete_variants() -> None:
    """Old PBE mechanisms should have semantic product-test coverage."""
    assert hasattr(test_pbe, "_LEGACY_PBE_CASES")
    legacy_cases = test_pbe._LEGACY_PBE_CASES

    covered = {int(case.mechanism) for case in legacy_cases}

    assert covered == {
        int(CKM_PBE_MD2_DES_CBC),
        int(CKM_PBE_MD5_DES_CBC),
        int(CKM_PBE_SHA1_RC4_128),
        int(CKM_PBE_SHA1_RC4_40),
        int(CKM_PBE_SHA1_RC2_128_CBC),
        int(CKM_PBE_SHA1_RC2_40_CBC),
    }
