from __future__ import annotations

from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKK_AES,
    CKO_SECRET_KEY,
)
from pkcs11_check.testcases import test_mech_wrap
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import MechConfig


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
