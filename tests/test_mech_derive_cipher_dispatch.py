"""Meta-tests for generic cipher encrypt-data derive dispatch."""

from __future__ import annotations

import ctypes

from pkcs11_check.raw.types_std import (
    CK_ARIA_CBC_ENCRYPT_DATA_PARAMS,
    CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS,
    CK_SEED_CBC_ENCRYPT_DATA_PARAMS,
    CKK_ARIA,
    CKK_CAMELLIA,
    CKK_SEED,
    CKM_ARIA_CBC_ENCRYPT_DATA,
    CKM_ARIA_ECB_ENCRYPT_DATA,
    CKM_ARIA_KEY_GEN,
    CKM_CAMELLIA_CBC_ENCRYPT_DATA,
    CKM_CAMELLIA_ECB_ENCRYPT_DATA,
    CKM_CAMELLIA_KEY_GEN,
    CKM_SEED_CBC_ENCRYPT_DATA,
    CKM_SEED_ECB_ENCRYPT_DATA,
    CKM_SEED_KEY_GEN,
)
from pkcs11_check.testcases import test_mech_derive as tmd


def test_cipher_encrypt_data_dispatch_covers_regional_cipher_families() -> None:
    cases = tmd._CIPHER_ENCRYPT_DATA_DERIVE_CASES

    expected = {
        int(CKM_CAMELLIA_ECB_ENCRYPT_DATA): (
            "CAMELLIA_KEY_GEN",
            int(CKM_CAMELLIA_KEY_GEN),
            int(CKK_CAMELLIA),
            "ecb",
            None,
        ),
        int(CKM_CAMELLIA_CBC_ENCRYPT_DATA): (
            "CAMELLIA_KEY_GEN",
            int(CKM_CAMELLIA_KEY_GEN),
            int(CKK_CAMELLIA),
            "cbc",
            CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS,
        ),
        int(CKM_ARIA_ECB_ENCRYPT_DATA): (
            "ARIA_KEY_GEN",
            int(CKM_ARIA_KEY_GEN),
            int(CKK_ARIA),
            "ecb",
            None,
        ),
        int(CKM_ARIA_CBC_ENCRYPT_DATA): (
            "ARIA_KEY_GEN",
            int(CKM_ARIA_KEY_GEN),
            int(CKK_ARIA),
            "cbc",
            CK_ARIA_CBC_ENCRYPT_DATA_PARAMS,
        ),
        int(CKM_SEED_ECB_ENCRYPT_DATA): (
            "SEED_KEY_GEN",
            int(CKM_SEED_KEY_GEN),
            int(CKK_SEED),
            "ecb",
            None,
        ),
        int(CKM_SEED_CBC_ENCRYPT_DATA): (
            "SEED_KEY_GEN",
            int(CKM_SEED_KEY_GEN),
            int(CKK_SEED),
            "cbc",
            CK_SEED_CBC_ENCRYPT_DATA_PARAMS,
        ),
    }

    for mech_id, (keygen_name, keygen_mech, key_type, mode, params_cls) in expected.items():
        case = cases[mech_id]
        assert case.keygen_name == keygen_name
        assert int(case.keygen_mech) == keygen_mech
        assert int(case.key_type) == key_type
        assert case.mode == mode
        assert case.cbc_params_cls is params_cls
        assert case.block_size == 16


def test_cipher_cbc_encrypt_data_packer_uses_family_specific_struct() -> None:
    iv = bytes(range(16))
    data = b"derive__test__01"

    for mech_id, params_cls in [
        (CKM_CAMELLIA_CBC_ENCRYPT_DATA, CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS),
        (CKM_ARIA_CBC_ENCRYPT_DATA, CK_ARIA_CBC_ENCRYPT_DATA_PARAMS),
        (CKM_SEED_CBC_ENCRYPT_DATA, CK_SEED_CBC_ENCRYPT_DATA_PARAMS),
    ]:
        packed = tmd._mech_block_cbc_encrypt_data(mech_id, params_cls, iv=iv, data=data)

        assert packed.ck.mechanism == mech_id
        assert isinstance(packed.params, params_cls)
        assert packed.ck.ulParameterLen == ctypes.sizeof(params_cls)
        assert bytes(packed.params.iv) == iv
        assert packed.params.length == len(data)
        assert ctypes.string_at(packed.params.pData, packed.params.length) == data
