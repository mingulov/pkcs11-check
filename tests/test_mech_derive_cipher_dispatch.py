"""Meta-tests for generic cipher encrypt-data derive dispatch."""

from __future__ import annotations

import ctypes
import subprocess
import sys
from pathlib import Path

import pytest

from pkcs11_check.raw.types_std import (
    CK_ARIA_CBC_ENCRYPT_DATA_PARAMS,
    CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS,
    CK_DES_CBC_ENCRYPT_DATA_PARAMS,
    CK_SEED_CBC_ENCRYPT_DATA_PARAMS,
    CKK_ARIA,
    CKK_CAMELLIA,
    CKK_DES,
    CKK_DES3,
    CKK_SEED,
    CKM_ARIA_CBC_ENCRYPT_DATA,
    CKM_ARIA_ECB_ENCRYPT_DATA,
    CKM_ARIA_KEY_GEN,
    CKM_CAMELLIA_CBC_ENCRYPT_DATA,
    CKM_CAMELLIA_ECB_ENCRYPT_DATA,
    CKM_CAMELLIA_KEY_GEN,
    CKM_DES3_CBC_ENCRYPT_DATA,
    CKM_DES3_KEY_GEN,
    CKM_DES_CBC_ENCRYPT_DATA,
    CKM_DES_KEY_GEN,
    CKM_SEED_CBC_ENCRYPT_DATA,
    CKM_SEED_ECB_ENCRYPT_DATA,
    CKM_SEED_KEY_GEN,
)
from pkcs11_check.testcases import test_mech_derive as tmd

REPO = Path(__file__).resolve().parents[1]


def test_cipher_encrypt_data_dispatch_covers_regional_cipher_families() -> None:
    cases = tmd._CIPHER_ENCRYPT_DATA_DERIVE_CASES

    expected = {
        int(CKM_DES_CBC_ENCRYPT_DATA): (
            "DES_KEY_GEN",
            int(CKM_DES_KEY_GEN),
            int(CKK_DES),
            "cbc",
            CK_DES_CBC_ENCRYPT_DATA_PARAMS,
            8,
        ),
        int(CKM_DES3_CBC_ENCRYPT_DATA): (
            "DES3_KEY_GEN",
            int(CKM_DES3_KEY_GEN),
            int(CKK_DES3),
            "cbc",
            CK_DES_CBC_ENCRYPT_DATA_PARAMS,
            8,
        ),
        int(CKM_CAMELLIA_ECB_ENCRYPT_DATA): (
            "CAMELLIA_KEY_GEN",
            int(CKM_CAMELLIA_KEY_GEN),
            int(CKK_CAMELLIA),
            "ecb",
            None,
            16,
        ),
        int(CKM_CAMELLIA_CBC_ENCRYPT_DATA): (
            "CAMELLIA_KEY_GEN",
            int(CKM_CAMELLIA_KEY_GEN),
            int(CKK_CAMELLIA),
            "cbc",
            CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS,
            16,
        ),
        int(CKM_ARIA_ECB_ENCRYPT_DATA): (
            "ARIA_KEY_GEN",
            int(CKM_ARIA_KEY_GEN),
            int(CKK_ARIA),
            "ecb",
            None,
            16,
        ),
        int(CKM_ARIA_CBC_ENCRYPT_DATA): (
            "ARIA_KEY_GEN",
            int(CKM_ARIA_KEY_GEN),
            int(CKK_ARIA),
            "cbc",
            CK_ARIA_CBC_ENCRYPT_DATA_PARAMS,
            16,
        ),
        int(CKM_SEED_ECB_ENCRYPT_DATA): (
            "SEED_KEY_GEN",
            int(CKM_SEED_KEY_GEN),
            int(CKK_SEED),
            "ecb",
            None,
            16,
        ),
        int(CKM_SEED_CBC_ENCRYPT_DATA): (
            "SEED_KEY_GEN",
            int(CKM_SEED_KEY_GEN),
            int(CKK_SEED),
            "cbc",
            CK_SEED_CBC_ENCRYPT_DATA_PARAMS,
            16,
        ),
    }

    for mech_id, (
        keygen_name,
        keygen_mech,
        key_type,
        mode,
        params_cls,
        block_size,
    ) in expected.items():
        case = cases[mech_id]
        assert case.keygen_name == keygen_name
        assert int(case.keygen_mech) == keygen_mech
        assert int(case.key_type) == key_type
        assert case.mode == mode
        assert case.cbc_params_cls is params_cls
        assert case.block_size == block_size


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


def test_des_cbc_encrypt_data_packer_uses_eight_byte_iv_and_blocks() -> None:
    iv = bytes(range(8))
    data = b"12345678abcdefgh"

    for mech_id, params_cls in [
        (CKM_DES_CBC_ENCRYPT_DATA, CK_DES_CBC_ENCRYPT_DATA_PARAMS),
        (CKM_DES3_CBC_ENCRYPT_DATA, CK_DES_CBC_ENCRYPT_DATA_PARAMS),
    ]:
        packed = tmd._mech_block_cbc_encrypt_data(mech_id, params_cls, iv=iv, data=data)

        assert packed.ck.mechanism == mech_id
        assert isinstance(packed.params, params_cls)
        assert packed.ck.ulParameterLen == ctypes.sizeof(params_cls)
        assert bytes(packed.params.iv) == iv
        assert packed.params.length == len(data)
        assert ctypes.string_at(packed.params.pData, packed.params.length) == data


@pytest.mark.parametrize(
    ("iv", "data", "message"),
    [
        (bytes(7), b"12345678", "8 bytes"),
        (bytes(9), b"12345678", "8 bytes"),
        (bytes(8), b"1234567", "8-byte multiple"),
        (bytes(8), b"123456789", "8-byte multiple"),
    ],
)
def test_des_cbc_encrypt_data_packer_rejects_non_block_aligned_inputs(
    iv: bytes, data: bytes, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        tmd._mech_block_cbc_encrypt_data(
            CKM_DES_CBC_ENCRYPT_DATA,
            CK_DES_CBC_ENCRYPT_DATA_PARAMS,
            iv=iv,
            data=data,
        )


def test_des_kdf_file_is_selected_by_derive_marker() -> None:
    target = "src/pkcs11_check/testcases/test_des_kdf.py"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-o",
            "addopts=",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            "-m",
            "derive",
            target,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=REPO,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    selected = [line for line in proc.stdout.splitlines() if "::" in line]
    assert len(selected) == 2
    assert all(
        "test_des_cbc_encrypt_data_derive_matches_oracle_and_truncates" in n for n in selected
    )
