"""P11C-008: CKM_CAMELLIA_CTR registry entry must carry a CTR param recipe."""

from __future__ import annotations

from pkcs11_check.raw.types_std import (
    CK_AES_CTR_PARAMS,
    CKM_CAMELLIA_CTR,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases.conftest import classify_negative_rv
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_helpers import build_test_params
from pkcs11_check.testcases.mechanism_registry import get_config
from pkcs11_check.testcases.test_mech_negative import (
    _MISSING_REQUIRED_PARAM_RVS,
    _skip_if_not_required_param_registry_case,
)


def test_camellia_ctr_recipe_builds_ctr_params() -> None:
    """CAMELLIA_CTR registry recipe must build CTR counter-block params."""
    config = get_config(int(CKM_CAMELLIA_CTR))
    assert config is not None
    assert config.param_required is True
    assert config.param_recipe.style == "ctr"
    assert config.param_recipe.defaults.get("counter_bits") == 128

    mech = build_test_params(int(CKM_CAMELLIA_CTR), config.param_recipe)
    assert mech is not None
    assert not isinstance(mech, str)
    assert mech.ck.mechanism == int(CKM_CAMELLIA_CTR)
    assert isinstance(mech.params, CK_AES_CTR_PARAMS)
    assert mech.params.ulCounterBits == 128


def test_camellia_ctr_null_param_negative_classifies() -> None:
    """param_required stays True so the NULL-param negative still applies and classifies."""
    config = get_config(int(CKM_CAMELLIA_CTR))
    assert config is not None
    entry = MechEntry(
        mech_id=int(CKM_CAMELLIA_CTR),
        mech_name="CKM_CAMELLIA_CTR",
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=config,
    )
    _skip_if_not_required_param_registry_case(entry)

    assert CKR_MECHANISM_PARAM_INVALID in _MISSING_REQUIRED_PARAM_RVS
    classify_negative_rv(
        CKR_MECHANISM_PARAM_INVALID,
        _MISSING_REQUIRED_PARAM_RVS,
        label="CKM_CAMELLIA_CTR C_EncryptInit with missing required params",
    )
