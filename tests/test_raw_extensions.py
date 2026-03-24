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
        packers={0x80010001: packer},
        inspectors={0x80010001: inspector},
    )

    assert lookup_struct("CK_IBM_KYBER_PARAMS", namespace="ibm") is not None
    assert lookup_packer(0x80010001, namespace="ibm") is packer
    assert lookup_inspector(0x80010001, namespace="ibm") is inspector


def test_extension_numeric_helper_collision_requires_namespace() -> None:
    from pkcs11_check.raw.extensions import lookup_inspector, lookup_packer, register_extension

    packer_a = lambda value: value
    packer_b = lambda value: value + 1
    inspector_a = lambda value: "a"
    inspector_b = lambda value: "b"

    register_extension(namespace="ibm", packers={0x80010003: packer_a}, inspectors={0x80010003: inspector_a})
    register_extension(namespace="acme", packers={0x80010003: packer_b}, inspectors={0x80010003: inspector_b})

    assert lookup_packer(0x80010003) is None
    assert lookup_inspector(0x80010003) is None
    assert lookup_packer(0x80010003, namespace="ibm") is packer_a
    assert lookup_inspector(0x80010003, namespace="acme") is inspector_b


def test_extension_namespaced_numeric_lookup_uses_vendor_symbol_mapping() -> None:
    from pkcs11_check.raw.extensions import lookup_inspector, lookup_packer, register_extension

    packer_ibm = lambda value: value
    inspector_ibm = lambda value: "ibm"

    register_extension(
        namespace="ibm",
        mechanisms={0x80010004: "CKM_IBM_SHARED_ID"},
        packers={"CKM_IBM_SHARED_ID": packer_ibm},
        inspectors={"CKM_IBM_SHARED_ID": inspector_ibm},
    )
    register_extension(namespace="acme", mechanisms={0x80010004: "CKM_ACME_SHARED_ID"})

    assert lookup_packer(0x80010004, namespace="ibm") is packer_ibm
    assert lookup_inspector(0x80010004, namespace="ibm") is inspector_ibm


def test_extension_global_numeric_lookup_does_not_leak_standard_symbol_fallback() -> None:
    from pkcs11_check.raw.extensions import lookup_inspector, register_extension
    from pkcs11_check.raw.types_std import CKM_AES_KEY_GEN

    inspector = lambda value: "vendor-standard-name-leak"

    register_extension(namespace="ibm", inspectors={"CKM_AES_KEY_GEN": inspector})

    assert lookup_inspector(CKM_AES_KEY_GEN) is None
    assert lookup_inspector("CKM_AES_KEY_GEN") is inspector
