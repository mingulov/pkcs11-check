from __future__ import annotations

import ctypes


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


def test_inspect_sized_fault_renders_note_pointer_and_explicit_length() -> None:
    from pkcs11_check.raw.faults import nonnull_zero_length_bytes
    from pkcs11_check.raw.inspect import render_sized_fault

    text = render_sized_fault(nonnull_zero_length_bytes(b"abc"))
    assert "nonnull pointer with zero length" in text
    assert "kind=bytes" in text
    assert "len=0 explicit" in text


def test_inspect_attribute_shows_preview_for_ctypes_byte_array() -> None:
    from pkcs11_check.raw.inspect import render_attribute
    from pkcs11_check.raw.pack import attr_array

    text = render_attribute(attr_array(0x00000011, [1, 2, 3], ctype=ctypes.c_ubyte))
    assert "kind=bytes" in text
    assert "preview=010203" in text


def test_inspect_mechanism_can_render_colliding_vendor_ids_by_namespace() -> None:
    from pkcs11_check.raw.extensions import register_extension
    from pkcs11_check.raw.inspect import render_mechanism
    from pkcs11_check.raw.pack import mech_simple

    register_extension(
        namespace="ibm",
        mechanisms={0x80010030: "CKM_IBM_COLLIDE"},
        inspectors={0x80010030: lambda _value: "ibm-detail"},
    )
    register_extension(
        namespace="acme",
        mechanisms={0x80010030: "CKM_ACME_COLLIDE"},
        inspectors={0x80010030: lambda _value: "acme-detail"},
    )

    ibm_text = render_mechanism(mech_simple(0x80010030), namespace="ibm")
    acme_text = render_mechanism(mech_simple(0x80010030), namespace="acme")

    assert "CKM_IBM_COLLIDE" in ibm_text
    assert "ibm-detail" in ibm_text
    assert "CKM_ACME_COLLIDE" in acme_text
    assert "acme-detail" in acme_text
