"""Generated AEAD wrap parameter output tests."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import (
    mech_ccm_wrap,
    mech_ccm_wrap_generated_nonce,
    mech_gcm_wrap,
    mech_gcm_wrap_generated_iv,
)
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    get_mechanism_info,
    read_attributes,
    unwrap_key,
    wrap_key,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_WRAP,
    CKF_UNWRAP,
    CKF_WRAP,
    CKK_AES,
    CKM,
    CKM_AES_CCM,
    CKM_AES_GCM,
    CKO_SECRET_KEY,
)
from pkcs11_check.testcases.conftest import skip_if_mech_param_unsupported

pytestmark = [pytest.mark.keymgmt, pytest.mark.wrap, pytest.mark.requires_v32]


def _require_wrap_flags(rs: Any, mechanism: CKM | int, name: str) -> None:
    info = get_mechanism_info(rs.raw, rs.slot_id, mechanism)
    flags = info["flags"]
    if not (flags & int(CKF_WRAP)) or not (flags & int(CKF_UNWRAP)):
        pytest.skip(f"{name} does not advertise CKF_WRAP and CKF_UNWRAP")


def _make_keys(rs: Any) -> tuple[int, int, bytes]:
    wrap_h = gen_aes_key(
        rs.raw,
        rs.sh,
        256,
        attrs={
            CKA_WRAP: True,
            CKA_UNWRAP: True,
            CKA_ENCRYPT: True,
            CKA_DECRYPT: True,
            CKA_TOKEN: False,
        },
    )
    target = gen_aes_key(
        rs.raw,
        rs.sh,
        128,
        attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False, CKA_TOKEN: False},
    )
    original = read_attributes(rs.raw, rs.sh, target, [CKA_VALUE])[CKA_VALUE]
    assert isinstance(original, bytes)
    return wrap_h, target, original


def test_gcm_wrap_generated_iv_roundtrip(p11_raw_session: Any, p11_interface_version: str) -> None:
    rs = p11_raw_session
    if p11_interface_version != "3.2":
        pytest.skip("CK_GCM_WRAP_PARAMS generated IV requires v3.2")
    if not rs.has_mechanism("AES_GCM"):
        pytest.skip("CKM_AES_GCM not supported")
    _require_wrap_flags(rs, CKM_AES_GCM, "CKM_AES_GCM")

    wrap_h, target, original = _make_keys(rs)
    unwrapped = 0
    try:
        aad = b"gcm wrap generated iv"
        wrap_mech = mech_gcm_wrap_generated_iv(CKM_AES_GCM, iv_len=12, aad=aad, tag_bits=128)
        try:
            wrapped = wrap_key(rs.raw, rs.sh, wrap_h, target, CKM_AES_GCM, mech_param=wrap_mech)
        except AssertionError as exc:
            skip_if_mech_param_unsupported(exc, "CK_GCM_WRAP_PARAMS generated IV C_WrapKey")

        iv = wrap_mech.buffer_bytes("iv")
        assert any(iv), "C_WrapKey accepted CKG_GENERATE but did not write pIv"

        unwrap_mech = mech_gcm_wrap(CKM_AES_GCM, iv, aad=aad, tag_bits=128)
        unwrapped = unwrap_key(
            rs.raw,
            rs.sh,
            wrap_h,
            wrapped,
            CKM_AES_GCM,
            attrs={
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_AES,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
            },
            mech_param=unwrap_mech,
        )
        value = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE])[CKA_VALUE]
        assert value == original
    finally:
        destroy_quietly(rs.raw, rs.sh, unwrapped)
        destroy_quietly(rs.raw, rs.sh, wrap_h)
        destroy_quietly(rs.raw, rs.sh, target)


def test_ccm_wrap_generated_nonce_roundtrip(
    p11_raw_session: Any, p11_interface_version: str
) -> None:
    rs = p11_raw_session
    if p11_interface_version != "3.2":
        pytest.skip("CK_CCM_WRAP_PARAMS generated nonce requires v3.2")
    if not rs.has_mechanism("AES_CCM"):
        pytest.skip("CKM_AES_CCM not supported")
    _require_wrap_flags(rs, CKM_AES_CCM, "CKM_AES_CCM")

    wrap_h, target, original = _make_keys(rs)
    unwrapped = 0
    try:
        aad = b"ccm wrap generated nonce"
        wrap_mech = mech_ccm_wrap_generated_nonce(
            CKM_AES_CCM,
            data_len=len(original),
            nonce_len=12,
            aad=aad,
            mac_len=16,
        )
        try:
            wrapped = wrap_key(rs.raw, rs.sh, wrap_h, target, CKM_AES_CCM, mech_param=wrap_mech)
        except AssertionError as exc:
            skip_if_mech_param_unsupported(exc, "CK_CCM_WRAP_PARAMS generated nonce C_WrapKey")

        nonce = wrap_mech.buffer_bytes("nonce")
        assert any(nonce), "C_WrapKey accepted CKG_GENERATE but did not write pNonce"

        unwrap_mech = mech_ccm_wrap(
            CKM_AES_CCM,
            nonce,
            data_len=len(original),
            aad=aad,
            mac_len=16,
        )
        unwrapped = unwrap_key(
            rs.raw,
            rs.sh,
            wrap_h,
            wrapped,
            CKM_AES_CCM,
            attrs={
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_AES,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
            },
            mech_param=unwrap_mech,
        )
        value = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE])[CKA_VALUE]
        assert value == original
    finally:
        destroy_quietly(rs.raw, rs.sh, unwrapped)
        destroy_quietly(rs.raw, rs.sh, wrap_h)
        destroy_quietly(rs.raw, rs.sh, target)
