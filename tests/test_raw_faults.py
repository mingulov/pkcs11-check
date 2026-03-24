from __future__ import annotations


def test_null_pointer_and_zero_length_are_distinct() -> None:
    from pkcs11_check.raw.faults import null_pointer, zero_length

    assert null_pointer() != zero_length()


def test_truncated_struct_keeps_explicit_short_length() -> None:
    from pkcs11_check.raw.faults import truncated_struct
    from pkcs11_check.raw.types_std import CK_GCM_PARAMS

    value = truncated_struct(CK_GCM_PARAMS, keep=8)
    assert value.explicit_length == 8
