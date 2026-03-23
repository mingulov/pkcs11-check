from __future__ import annotations


def test_generated_standard_c_methods() -> None:
    from pkcs11_check.raw import metadata_std

    names = set(metadata_std.FUNCTION_SIGNATURES)
    assert "C_GetFunctionList" in names
    assert "C_CancelFunction" in names
    assert "C_DigestEncryptUpdate" in names
    assert len(names) >= 104


def test_rawpkcs11_available_function_names_are_explicit() -> None:
    from pkcs11_check.raw.api import RawPKCS11

    raw = object.__new__(RawPKCS11)
    raw._funcs = {"C_GetFunctionList": object(), "C_CancelFunction": object()}

    assert raw.available_function_names() == {"C_GetFunctionList", "C_CancelFunction"}


def test_raw_api_never_auto_raises() -> None:
    from pkcs11_check.raw.rv import ckr_name

    assert ckr_name(0x00000007) == "CKR_ARGUMENTS_BAD"
