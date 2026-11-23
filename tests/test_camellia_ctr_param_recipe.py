"""P11C-008: CKM_CAMELLIA_CTR registry entry must carry a CTR param recipe.

fw#92: a correct CTR keystream depends on the counter block, not on the width
alone: from cb=0, widths 32 and 64 emit identical counter sequences for short
plaintexts, so a bits-only ciphertext comparison is a false oracle. The
reference below models PKCS#11 CTR (low `bits` bits of cb increment
big-endian) over real AES so both the bug and the fix premise execute.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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


_KEY = bytes(range(16))
_PLAINTEXT = b"CTR nonce independence test!!"  # 29 bytes, as in the testcase


def _ctr_encrypt(key: bytes, bits: int, cb: bytes, plaintext: bytes) -> bytes:
    """Reference CTR: low `bits` bits of cb increment, AES-ECB keystream."""
    assert len(cb) == 16 and 0 < bits <= 128
    base = int.from_bytes(cb, "big")
    low_mask = (1 << bits) - 1
    high = base & ~low_mask
    low = base & low_mask
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    out = bytearray()
    for index in range((len(plaintext) + 15) // 16):
        block = (high | ((low + index) & low_mask)).to_bytes(16, "big")
        keystream = encryptor.update(block)
        chunk = plaintext[index * 16 : (index + 1) * 16]
        out.extend(a ^ b for a, b in zip(chunk, keystream))
    return bytes(out)


def test_bits_only_difference_yields_identical_ciphertext() -> None:
    """The old oracle (bits 32 vs 64, same cb) is false on a correct CTR."""
    cb = bytes(16)
    assert _ctr_encrypt(_KEY, 32, cb, _PLAINTEXT) == _ctr_encrypt(_KEY, 64, cb, _PLAINTEXT)


def test_different_counter_blocks_yield_different_ciphertext() -> None:
    """The new oracle (differ cb at equal bits) holds on a correct CTR."""
    cb1 = bytes(16)
    cb2 = bytes(15) + b"\x01"
    assert _ctr_encrypt(_KEY, 64, cb1, _PLAINTEXT) != _ctr_encrypt(_KEY, 64, cb2, _PLAINTEXT)
