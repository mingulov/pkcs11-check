from __future__ import annotations


def test_null_pointer_and_zero_length_are_distinct() -> None:
    from pkcs11_check.raw.faults import null_pointer, zero_length

    assert null_pointer() != zero_length()


def test_truncated_struct_keeps_explicit_short_length() -> None:
    from pkcs11_check.raw.faults import truncated_struct
    from pkcs11_check.raw.types_std import CK_GCM_PARAMS

    value = truncated_struct(CK_GCM_PARAMS, keep=8)
    assert value.explicit_length == 8


def test_nonnull_zero_length_bytes_model_is_first_class() -> None:
    from pkcs11_check.raw.faults import nonnull_zero_length_bytes

    value = nonnull_zero_length_bytes(b"abc")
    assert value.pointer_arg.kind == "bytes"
    assert value.length_arg.value == 0
    assert value.length_arg.explicit is True


def test_incorrect_explicit_length_keeps_live_storage_metadata() -> None:
    from pkcs11_check.raw.faults import incorrect_explicit_length_bytes

    value = incorrect_explicit_length_bytes(b"abcd", claim=9)
    assert value.pointer_arg.kind == "bytes"
    assert value.pointer_arg.native_length == 5
    assert value.length_arg.value == 9


def test_mismatched_template_count_keeps_actual_and_claimed_counts() -> None:
    from pkcs11_check.raw.faults import mismatched_template_count
    from pkcs11_check.raw.pack import attr_bool

    value = mismatched_template_count(attr_bool(0x00000104, True), claim_count=4)
    assert value.actual_count == 1
    assert value.claimed_count == 4
    assert value.pointer_arg.kind == "array"
