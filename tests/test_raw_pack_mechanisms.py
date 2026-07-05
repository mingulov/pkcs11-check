"""Golden field/pointer tests for the raw mechanism packers not covered by test_raw_pack.py.

These packers build CK_*_PARAMS structs with pointer/offset arithmetic and nested writable
pointers -- the same surface that shipped the `make_caller` offset bug -- so each is pinned
here with byte/field-level assertions (mechanism id, scalar fields, pointer backing and its
length, and NULL where the spec expects it). Modelled on tests/test_raw_pack.py.
"""

from __future__ import annotations

import ctypes

from pkcs11_check.raw.pack_mechanisms import (
    _alloc_writable_pointer,
    mech_ccm,
    mech_ecdh_aes_kw,
    mech_rc2,
    mech_rc2_cbc,
    mech_sign_context,
    mech_ssl3_master_key_derive,
    mech_tls12_extended_master_key_derive,
    mech_tls12_master_key_derive,
    mech_tls_kdf,
    mech_tls_mac,
    mech_wtls_master_key_derive,
)
from pkcs11_check.raw.types_std import (
    CK_AES_CCM_PARAMS,
    CK_ECDH_AES_KEY_WRAP_PARAMS,
    CK_RC2_CBC_PARAMS,
    CK_SIGN_ADDITIONAL_CONTEXT,
    CK_SSL3_MASTER_KEY_DERIVE_PARAMS,
    CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS,
    CK_TLS12_MASTER_KEY_DERIVE_PARAMS,
    CK_TLS_KDF_PARAMS,
    CK_TLS_MAC_PARAMS,
    CK_ULONG,
    CK_WTLS_MASTER_KEY_DERIVE_PARAMS,
    CKD_SHA256_KDF,
    CKH_HEDGE_PREFERRED,
    CKM_AES_CCM,
    CKM_ECDH_AES_KEY_WRAP,
    CKM_ML_DSA,
    CKM_RC2_CBC,
    CKM_RC2_ECB,
    CKM_SHA256,
    CKM_SSL3_MASTER_KEY_DERIVE,
    CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
    CKM_TLS12_KDF,
    CKM_TLS12_MAC,
    CKM_TLS12_MASTER_KEY_DERIVE,
    CKM_WTLS_MASTER_KEY_DERIVE,
)


def _read(ptr: int | None, length: int) -> bytes:
    assert ptr is not None  # a c_void_p field reads back as int | None
    return ctypes.string_at(ptr, length)


def test_alloc_writable_pointer_aims_field_at_sized_buffer() -> None:
    class _Holder(ctypes.Structure):
        _fields_ = [("p", ctypes.c_void_p), ("n", ctypes.c_ulong)]

    h = _Holder()
    buf = _alloc_writable_pointer(h, "p", 16)
    assert len(buf) == 16
    assert bytes(buf) == b"\x00" * 16  # demand-zeroed
    # the struct field points AT the returned buffer, and provider writes are visible
    assert h.p == ctypes.cast(buf, ctypes.c_void_p).value
    ctypes.memmove(h.p, b"ABCD", 4)
    assert bytes(buf[:4]) == b"ABCD"


def test_mech_ccm_packs_lengths_and_nonce() -> None:
    nonce = b"\x01" * 12
    aad = b"\x02" * 5
    mech = mech_ccm(CKM_AES_CCM, nonce, data_len=32, aad=aad, mac_len=16)
    assert mech.ck.mechanism == CKM_AES_CCM
    params = mech.params
    assert isinstance(params, CK_AES_CCM_PARAMS)
    assert params.ulDataLen == 32
    assert params.ulNonceLen == 12
    assert params.ulMACLen == 16
    assert params.ulAADLen == 5
    assert _read(params.pNonce, params.ulNonceLen) == nonce
    assert _read(params.pAAD, params.ulAADLen) == aad


def test_mech_ccm_null_aad_is_null_pointer() -> None:
    mech = mech_ccm(CKM_AES_CCM, b"\x00" * 12, data_len=0, aad=None, mac_len=8)
    assert mech.params.pAAD is None
    assert mech.params.ulAADLen == 0


def test_mech_rc2_is_single_ck_ulong() -> None:
    mech = mech_rc2(CKM_RC2_ECB, effective_bits=64)
    assert mech.ck.mechanism == CKM_RC2_ECB
    # CK_RC2_PARAMS is a bare CK_ULONG
    assert len(mech.storage) == ctypes.sizeof(CK_ULONG)
    assert CK_ULONG.from_buffer_copy(bytes(mech.storage)).value == 64


def test_mech_rc2_cbc_packs_effective_bits_and_iv() -> None:
    iv = bytes(range(8))
    mech = mech_rc2_cbc(CKM_RC2_CBC, effective_bits=128, iv=iv)
    params = mech.params
    assert isinstance(params, CK_RC2_CBC_PARAMS)
    assert params.ulEffectiveBits == 128
    assert bytes(params.iv) == iv


def test_mech_rc2_cbc_defaults_to_zero_iv() -> None:
    params = mech_rc2_cbc(CKM_RC2_CBC, effective_bits=64).params
    assert bytes(params.iv) == b"\x00" * 8


def test_mech_sign_context_default_hedge_and_context() -> None:
    ctx = b"context-bytes"
    mech = mech_sign_context(CKM_ML_DSA, context=ctx)
    params = mech.params
    assert isinstance(params, CK_SIGN_ADDITIONAL_CONTEXT)
    assert params.hedgeVariant == CKH_HEDGE_PREFERRED
    assert params.ulContextLen == len(ctx)
    assert _read(params.pContext, params.ulContextLen) == ctx


def test_mech_sign_context_null_context() -> None:
    params = mech_sign_context(CKM_ML_DSA, context=None).params
    assert params.pContext is None
    assert params.ulContextLen == 0


def test_mech_tls_mac_packs_three_scalars() -> None:
    mech = mech_tls_mac(
        CKM_TLS12_MAC, prf_hash_mechanism=CKM_SHA256, mac_length=12, server_or_client=1
    )
    params = mech.params
    assert isinstance(params, CK_TLS_MAC_PARAMS)
    assert params.prfHashMechanism == CKM_SHA256
    assert params.ulMacLength == 12
    assert params.ulServerOrClient == 1


def test_mech_tls_kdf_packs_label_randoms_and_null_context() -> None:
    label, cr, sr = b"key expansion", b"\x11" * 32, b"\x22" * 32
    mech = mech_tls_kdf(
        CKM_TLS12_KDF, prf_mechanism=CKM_SHA256, label=label, client_random=cr, server_random=sr
    )
    params = mech.params
    assert isinstance(params, CK_TLS_KDF_PARAMS)
    assert params.prfMechanism == CKM_SHA256
    assert _read(params.pLabel, params.ulLabelLength) == label
    assert params.RandomInfo.ulClientRandomLen == len(cr)
    assert params.RandomInfo.ulServerRandomLen == len(sr)
    assert _read(params.RandomInfo.pClientRandom, len(cr)) == cr
    assert params.pContextData is None
    assert params.ulContextDataLength == 0


def test_mech_ssl3_master_key_derive_version_pointer_toggles() -> None:
    cr, sr = b"\xaa" * 28, b"\xbb" * 28
    with_ver = mech_ssl3_master_key_derive(CKM_SSL3_MASTER_KEY_DERIVE, cr, sr, with_version=True)
    params = with_ver.params
    assert isinstance(params, CK_SSL3_MASTER_KEY_DERIVE_PARAMS)
    assert params.RandomInfo.ulClientRandomLen == len(cr)
    assert _read(params.RandomInfo.pServerRandom, len(sr)) == sr
    assert params.pVersion is not None  # module fills the negotiated version here
    no_ver = mech_ssl3_master_key_derive(CKM_SSL3_MASTER_KEY_DERIVE, cr, sr, with_version=False)
    assert no_ver.params.pVersion is None


def test_mech_tls12_master_key_derive_packs_prf_hash_and_version() -> None:
    cr, sr = b"\x01" * 28, b"\x02" * 28
    mech = mech_tls12_master_key_derive(CKM_TLS12_MASTER_KEY_DERIVE, cr, sr, hash_mech=CKM_SHA256)
    params = mech.params
    assert isinstance(params, CK_TLS12_MASTER_KEY_DERIVE_PARAMS)
    assert params.prfHashMechanism == CKM_SHA256
    assert params.RandomInfo.ulClientRandomLen == len(cr)
    assert params.pVersion is not None


def test_mech_wtls_master_key_derive_packs_digest_and_version() -> None:
    cr, sr = b"\x03" * 16, b"\x04" * 16
    mech = mech_wtls_master_key_derive(CKM_WTLS_MASTER_KEY_DERIVE, CKM_SHA256, cr, sr)
    params = mech.params
    assert isinstance(params, CK_WTLS_MASTER_KEY_DERIVE_PARAMS)
    assert params.DigestMechanism == CKM_SHA256
    assert params.RandomInfo.ulServerRandomLen == len(sr)
    assert params.pVersion is not None


def test_mech_tls12_extended_master_key_derive_packs_session_hash() -> None:
    sh = b"\x09" * 32
    mech = mech_tls12_extended_master_key_derive(
        CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE, CKM_SHA256, sh
    )
    params = mech.params
    assert isinstance(params, CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS)
    assert params.prfHashMechanism == CKM_SHA256
    assert params.ulSessionHashLen == len(sh)
    assert _read(params.pSessionHash, params.ulSessionHashLen) == sh
    assert params.pVersion is not None


def test_mech_ecdh_aes_kw_packs_bits_kdf_and_shared_data() -> None:
    shared = b"info-string"
    mech = mech_ecdh_aes_kw(
        CKM_ECDH_AES_KEY_WRAP, aes_key_bits=256, kdf=CKD_SHA256_KDF, shared_data=shared
    )
    params = mech.params
    assert isinstance(params, CK_ECDH_AES_KEY_WRAP_PARAMS)
    assert params.ulAESKeyBits == 256
    assert params.kdf == CKD_SHA256_KDF
    assert params.ulSharedDataLen == len(shared)
    assert _read(params.pSharedData, params.ulSharedDataLen) == shared
