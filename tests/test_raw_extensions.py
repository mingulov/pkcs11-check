from __future__ import annotations


def test_unknown_vendor_numeric_id_needs_no_registration() -> None:
    from pkcs11_check.raw.pack import mech_simple

    mech = mech_simple(0x80010001)
    assert mech.ck.mechanism == 0x80010001


def test_extension_registration_adds_names_without_blocking_execution() -> None:
    from pkcs11_check.raw.extensions import lookup_symbol_name, register_extension

    register_extension(namespace="ibm", mechanisms={0x80010001: "CKM_IBM_KYBER"})
    assert lookup_symbol_name("mechanisms", 0x80010001, namespace="ibm") == "CKM_IBM_KYBER"
    assert lookup_symbol_name("mechanisms", 0x80010001) == "CKM_IBM_KYBER"


def test_extension_collision_does_not_leak_across_namespaces() -> None:
    from pkcs11_check.raw.extensions import lookup_symbol_name, register_extension

    register_extension(namespace="ibm", mechanisms={0x80010002: "CKM_IBM_FOO"})
    register_extension(namespace="acme", mechanisms={0x80010002: "CKM_ACME_BAR"})

    assert lookup_symbol_name("mechanisms", 0x80010002) is None
    assert lookup_symbol_name("mechanisms", 0x80010002, namespace="ibm") == "CKM_IBM_FOO"
    assert lookup_symbol_name("mechanisms", 0x80010002, namespace="acme") == "CKM_ACME_BAR"


def test_extension_registry_supports_structs_packers_and_inspectors() -> None:
    from pkcs11_check.raw.extensions import (
        lookup_inspector,
        lookup_packer,
        lookup_struct,
        register_extension,
    )

    def packer(value: int) -> int:
        return value + 1

    def inspector(value: object) -> str:
        return repr(value)

    register_extension(
        namespace="ibm",
        structs={"CK_IBM_KYBER_PARAMS": object()},
        packers={"CKM_IBM_KYBER": packer},
        inspectors={"CKM_IBM_KYBER": inspector},
    )

    assert lookup_struct("CK_IBM_KYBER_PARAMS", namespace="ibm") is not None
    assert lookup_packer("CKM_IBM_KYBER", namespace="ibm") is packer
    assert lookup_inspector("CKM_IBM_KYBER", namespace="ibm") is inspector
