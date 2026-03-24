from __future__ import annotations


def test_pack_template_keeps_pointer_and_length_separate() -> None:
    from pkcs11_check.raw.pack import attr_ulong, explicit_length

    attr = attr_ulong(0x00000161, 32, length=explicit_length(1))
    assert attr.attribute.ulValueLen == 1


def test_pack_nested_templates_are_supported() -> None:
    from pkcs11_check.raw.pack import attr_bool, attr_template, template

    inner = template(attr_bool(0x00000104, True))
    outer = template(attr_template(0x40000211, inner))
    assert outer.count == 1


def test_pack_retains_pointer_and_length_provenance_metadata() -> None:
    from pkcs11_check.raw.pack import attr_bytes, explicit_length

    attr = attr_bytes(0x00000011, b"abcd", length=explicit_length(2))

    assert attr.pointer_arg.kind == "bytes"
    assert attr.pointer_arg.origin == "attr_bytes"
    assert attr.length_arg.explicit is True
    assert attr.length_arg.value == 2


def test_template_retains_packed_attributes_for_inspection() -> None:
    from pkcs11_check.raw.pack import attr_bool, attr_ulong, template

    value = template(attr_bool(0x00000104, True), attr_ulong(0x00000161, 32))

    assert len(value.attributes) == 2
    assert value.attributes[0].pointer_arg.kind == "scalar"
