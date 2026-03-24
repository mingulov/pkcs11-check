from __future__ import annotations


def test_inspect_mechanism_shows_symbol_and_length() -> None:
    from pkcs11_check.raw.inspect import render_mechanism
    from pkcs11_check.raw.pack import mech_simple
    from pkcs11_check.raw.types_std import CKM_AES_KEY_GEN

    text = render_mechanism(mech_simple(CKM_AES_KEY_GEN))
    assert "CKM_AES_KEY_GEN" in text
    assert "len=0" in text


def test_inspect_mechanism_surfaces_pointer_kind_and_length_mode() -> None:
    from pkcs11_check.raw.inspect import render_mechanism
    from pkcs11_check.raw.pack import explicit_length, mech_bytes
    from pkcs11_check.raw.types_std import CKM_AES_GCM

    text = render_mechanism(mech_bytes(CKM_AES_GCM, b"\x01\x02\x03\x04", length=explicit_length(2)))
    assert "kind=bytes" in text
    assert "len=2 explicit" in text
    assert "preview=01020304" in text


def test_inspect_template_renders_attribute_and_pointer_provenance() -> None:
    from pkcs11_check.raw.inspect import render_template
    from pkcs11_check.raw.pack import attr_bool, attr_bytes, template

    text = render_template(template(attr_bool(0x00000104, True), attr_bytes(0x00000011, b"ab")))
    assert "CKA_ENCRYPT" in text
    assert "kind=scalar" in text
    assert "kind=bytes" in text
    assert "native" in text


def test_inspect_count_fault_renders_claimed_actual_and_pointer_metadata() -> None:
    from pkcs11_check.raw.faults import mismatched_template_count
    from pkcs11_check.raw.inspect import render_count_fault
    from pkcs11_check.raw.pack import attr_bool

    text = render_count_fault(mismatched_template_count(attr_bool(0x00000104, True), claim_count=4))
    assert "claimed=4" in text
    assert "actual=1" in text
    assert "kind=array" in text
    assert "fault_mismatched_template_count" in text


def test_inspect_mechanism_prefers_numeric_extension_inspector_lookup() -> None:
    from pkcs11_check.raw.extensions import register_extension
    from pkcs11_check.raw.inspect import render_mechanism
    from pkcs11_check.raw.pack import mech_simple

    register_extension(
        namespace="ibm",
        mechanisms={0x80010021: "CKM_IBM_NUMERIC_ONLY"},
        inspectors={0x80010021: lambda _value: "numeric-inspector-hit"},
    )

    text = render_mechanism(mech_simple(0x80010021))
    assert "numeric-inspector-hit" in text
