from __future__ import annotations


def test_inspect_mechanism_shows_symbol_and_length() -> None:
    from pkcs11_check.raw.inspect import render_mechanism
    from pkcs11_check.raw.pack import mech_simple
    from pkcs11_check.raw.types_std import CKM_AES_KEY_GEN

    text = render_mechanism(mech_simple(CKM_AES_KEY_GEN))
    assert "CKM_AES_KEY_GEN" in text
    assert "len=0" in text
