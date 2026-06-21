"""Tests for mech_rsa_aes_key_wrap mechanism packer."""

import ctypes

import pytest

from pkcs11_check.raw.pack_mechanisms import mech_rsa_aes_key_wrap
from pkcs11_check.raw.types_std import (
    CK_RSA_AES_KEY_WRAP_PARAMS,
    CK_RSA_PKCS_OAEP_PARAMS,
    CKG_MGF1_SHA1,
    CKG_MGF1_SHA256,
    CKM_RSA_AES_KEY_WRAP,
    CKM_SHA256,
    CKM_SHA_1,
    CKZ_DATA_SPECIFIED,
)


def test_mech_rsa_aes_key_wrap_packs() -> None:
    """mech_rsa_aes_key_wrap returns a PackedMechanism with CKM_RSA_AES_KEY_WRAP.

    PackedMechanism.ck is the underlying CK_MECHANISM struct; .ck.mechanism holds
    the mechanism type and .ck.ulParameterLen holds the serialized param length.
    """
    m = mech_rsa_aes_key_wrap(aes_bits=256)
    assert int(m.ck.mechanism) == int(CKM_RSA_AES_KEY_WRAP)
    assert m.ck.ulParameterLen > 0  # non-empty params (CK_RSA_AES_KEY_WRAP_PARAMS struct)


def test_mech_rsa_aes_key_wrap_default_bits() -> None:
    """Default aes_bits is 256."""
    m = mech_rsa_aes_key_wrap()
    assert int(m.ck.mechanism) == int(CKM_RSA_AES_KEY_WRAP)
    assert m.ck.ulParameterLen > 0


def test_mech_rsa_aes_key_wrap_params_struct() -> None:
    """Default (sha1) uses CKM_SHA_1 / CKG_MGF1_SHA1."""
    m = mech_rsa_aes_key_wrap(aes_bits=256)
    # m.params is the CK_RSA_AES_KEY_WRAP_PARAMS
    params: CK_RSA_AES_KEY_WRAP_PARAMS = m.params  # type: ignore[assignment]
    assert params.ulAESKeyBits == 256

    # Recover the OAEP params from the void pointer
    oaep_ptr = ctypes.cast(params.pOAEPParams, ctypes.POINTER(CK_RSA_PKCS_OAEP_PARAMS))
    oaep: CK_RSA_PKCS_OAEP_PARAMS = oaep_ptr.contents
    assert int(oaep.hashAlg) == int(CKM_SHA_1)
    assert int(oaep.mgf) == int(CKG_MGF1_SHA1)
    assert int(oaep.source) == int(CKZ_DATA_SPECIFIED)
    assert oaep.pSourceData is None or oaep.ulSourceDataLen == 0


def test_mech_rsa_aes_key_wrap_sha256_explicit() -> None:
    """Explicit sha256 path uses CKM_SHA256 / CKG_MGF1_SHA256."""
    m = mech_rsa_aes_key_wrap(oaep_hash="sha256")
    params: CK_RSA_AES_KEY_WRAP_PARAMS = m.params  # type: ignore[assignment]
    oaep_ptr = ctypes.cast(params.pOAEPParams, ctypes.POINTER(CK_RSA_PKCS_OAEP_PARAMS))
    oaep: CK_RSA_PKCS_OAEP_PARAMS = oaep_ptr.contents
    assert int(oaep.hashAlg) == int(CKM_SHA256)
    assert int(oaep.mgf) == int(CKG_MGF1_SHA256)


def test_mech_rsa_aes_key_wrap_unknown_hash_raises() -> None:
    with pytest.raises(ValueError, match="oaep_hash"):
        mech_rsa_aes_key_wrap(oaep_hash="md5")


def test_mech_rsa_aes_key_wrap_128_bits() -> None:
    """128-bit AES variant packs the correct key size."""
    m = mech_rsa_aes_key_wrap(aes_bits=128)
    params: CK_RSA_AES_KEY_WRAP_PARAMS = m.params  # type: ignore[assignment]
    assert params.ulAESKeyBits == 128
