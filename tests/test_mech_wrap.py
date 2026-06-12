from __future__ import annotations

import pytest

from pkcs11_check.raw.types_std import (
    CK_AES_CTR_PARAMS,
    CK_CCM_WRAP_PARAMS,
    CK_GCM_WRAP_PARAMS,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKK_AES,
    CKM_AES_CCM,
    CKM_AES_CTR,
    CKM_AES_GCM,
    CKO_SECRET_KEY,
)
from pkcs11_check.testcases import test_mech_wrap
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import MechConfig, ParamRecipe


def _entry(input_constraint: str, *, flags: int = 0) -> MechEntry:
    return MechEntry(
        mech_id=0,
        mech_name="DUMMY",
        flags=flags,
        min_key_size=0,
        max_key_size=0,
        config=MechConfig(input_constraint=input_constraint),
    )


def test_target_unwrap_attrs_include_value_len_for_raw_rsa() -> None:
    attrs = test_mech_wrap._target_unwrap_attrs(_entry("raw_block"))

    assert attrs == {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_AES,
        CKA_DECRYPT: True,
        CKA_ENCRYPT: True,
        CKA_TOKEN: False,
        CKA_VALUE_LEN: 16,
    }


def test_target_unwrap_attrs_omit_value_len_for_non_raw_rsa() -> None:
    attrs = test_mech_wrap._target_unwrap_attrs(_entry("any"))

    assert attrs == {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_AES,
        CKA_DECRYPT: True,
        CKA_ENCRYPT: True,
        CKA_TOKEN: False,
    }


def test_raw_rsa_unwrap_hint_identifies_leading_bytes_bug() -> None:
    original = bytes.fromhex("00112233445566778899aabbccddeeff")
    decrypted_block = b"\x00" * 32 + original
    unwrapped_value = b"\x00" * len(original)

    hint = test_mech_wrap._raw_rsa_unwrap_hint(
        original,
        decrypted_block,
        unwrapped_value,
    )

    assert "leading bytes" in hint
    assert "trailing bytes" in hint


def test_raw_rsa_unwrap_hint_empty_without_known_pattern() -> None:
    original = bytes.fromhex("00112233445566778899aabbccddeeff")
    decrypted_block = b"\xff" * 32 + original
    unwrapped_value = original

    assert test_mech_wrap._raw_rsa_unwrap_hint(original, decrypted_block, unwrapped_value) == ""


def test_make_wrap_mech_param_builds_ctr_params_without_registry_recipe() -> None:
    entry = MechEntry(
        mech_id=int(CKM_AES_CTR),
        mech_name="CKM_AES_CTR",
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=None,
    )

    try:
        mech = test_mech_wrap._make_wrap_mech_param(entry)
    except pytest.skip.Exception as exc:
        raise AssertionError(
            f"CKM_AES_CTR wrap params should be built, not skipped: {exc}"
        ) from exc

    assert mech.ck.mechanism == CKM_AES_CTR
    params = mech.params
    assert isinstance(params, CK_AES_CTR_PARAMS)
    assert params.ulCounterBits == 128


def test_make_wrap_mech_param_builds_gcm_wrap_params() -> None:
    entry = MechEntry(
        mech_id=int(CKM_AES_GCM),
        mech_name="CKM_AES_GCM",
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=MechConfig(
            param_required=True,
            param_recipe=ParamRecipe("gcm", {"iv_len": 12, "tag_bits": 128}),
        ),
    )

    try:
        mech = test_mech_wrap._make_wrap_mech_param(entry)
    except pytest.skip.Exception as exc:
        raise AssertionError(
            f"CKM_AES_GCM wrap params should be built, not skipped: {exc}"
        ) from exc

    assert mech.ck.mechanism == CKM_AES_GCM
    params = mech.params
    assert isinstance(params, CK_GCM_WRAP_PARAMS)
    assert params.ulIvLen == 12
    assert params.ulIvFixedBits == 0
    assert params.ivGenerator == 0
    assert params.ulTagBits == 128


def test_make_wrap_mech_param_builds_ccm_wrap_params() -> None:
    entry = MechEntry(
        mech_id=int(CKM_AES_CCM),
        mech_name="CKM_AES_CCM",
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=MechConfig(
            param_required=True,
            param_recipe=ParamRecipe("ccm", {"nonce_len": 7, "data_len": 32, "mac_len": 16}),
        ),
    )

    try:
        mech = test_mech_wrap._make_wrap_mech_param(entry)
    except pytest.skip.Exception as exc:
        raise AssertionError(
            f"CKM_AES_CCM wrap params should be built, not skipped: {exc}"
        ) from exc

    assert mech.ck.mechanism == CKM_AES_CCM
    params = mech.params
    assert isinstance(params, CK_CCM_WRAP_PARAMS)
    assert params.ulDataLen == 16
    assert params.ulNonceLen == 7
    assert params.ulNonceFixedBits == 0
    assert params.nonceGenerator == 0
    assert params.ulMACLen == 16
