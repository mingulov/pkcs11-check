"""Coverage guardrails for legacy PBE mechanism tests."""

from __future__ import annotations

from pkcs11_check.raw.types_std import (
    CKM_PBE_MD2_DES_CBC,
    CKM_PBE_MD5_CAST3_CBC,
    CKM_PBE_MD5_CAST128_CBC,
    CKM_PBE_MD5_CAST_CBC,
    CKM_PBE_MD5_DES_CBC,
    CKM_PBE_SHA1_CAST128_CBC,
    CKM_PBE_SHA1_RC2_40_CBC,
    CKM_PBE_SHA1_RC2_128_CBC,
    CKM_PBE_SHA1_RC4_40,
    CKM_PBE_SHA1_RC4_128,
)
from pkcs11_check.testcases import test_pbe
from pkcs11_check.testcases.mechanism_registry import MECHANISM_REGISTRY


def test_legacy_pbe_case_table_covers_obsolete_variants() -> None:
    """Old PBE mechanisms should have semantic product-test coverage."""
    assert hasattr(test_pbe, "_LEGACY_PBE_CASES")
    legacy_cases = test_pbe._LEGACY_PBE_CASES

    covered = {int(case.mechanism) for case in legacy_cases}

    assert covered == {
        int(CKM_PBE_MD2_DES_CBC),
        int(CKM_PBE_MD5_DES_CBC),
        int(CKM_PBE_MD5_CAST_CBC),
        int(CKM_PBE_MD5_CAST3_CBC),
        int(CKM_PBE_MD5_CAST128_CBC),
        int(CKM_PBE_SHA1_CAST128_CBC),
        int(CKM_PBE_SHA1_RC4_128),
        int(CKM_PBE_SHA1_RC4_40),
        int(CKM_PBE_SHA1_RC2_128_CBC),
        int(CKM_PBE_SHA1_RC2_40_CBC),
    }


def test_legacy_pbe_runtime_classifier_names_all_case_mechanisms() -> None:
    """Every legacy PBE semantic case should classify runtime rejects by name."""
    missing = [
        case.mechanism_name
        for case in test_pbe._LEGACY_PBE_CASES
        if int(case.mechanism) not in test_pbe._PBE_MECH_NAMES
    ]

    assert missing == []


def test_cast_pbe_registry_entries_use_pbe_parameter_recipe() -> None:
    """CAST-family PBE registry entries should build CK_PBE_PARAMS too."""
    for mechanism in (
        CKM_PBE_MD5_CAST_CBC,
        CKM_PBE_MD5_CAST3_CBC,
        CKM_PBE_MD5_CAST128_CBC,
        CKM_PBE_SHA1_CAST128_CBC,
    ):
        recipe = MECHANISM_REGISTRY[int(mechanism)].param_recipe
        assert recipe is not None
        assert recipe.style == "pbe"
