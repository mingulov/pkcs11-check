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
