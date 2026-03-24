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
    import pytest

    from pkcs11_check.raw.extensions import register_extension

    with pytest.raises(ValueError, match="unknown vendor mechanism helper key"):
        register_extension(namespace="ibm", inspectors={"CKM_AES_KEY_GEN": lambda value: value})


def test_extension_namespaced_numeric_lookup_does_not_fall_back_to_standard_name() -> None:
    import pytest

    from pkcs11_check.raw.extensions import register_extension

    with pytest.raises(ValueError, match="unknown vendor mechanism helper key"):
        register_extension(namespace="ibm", inspectors={"CKM_AES_KEY_GEN": lambda value: value})


def test_extension_read_only_lookup_does_not_create_namespace() -> None:
    from pkcs11_check.raw import extensions

    before = set(extensions._EXTENSIONS)
    assert extensions.lookup_inspector(0x8FFF0001, namespace="ghost") is None
    assert set(extensions._EXTENSIONS) == before


def test_extension_global_numeric_lookup_uses_unique_vendor_symbolic_helper() -> None:
    from pkcs11_check.raw.extensions import lookup_inspector, register_extension

    inspector = lambda value: "vendor-numeric-fallback"

    register_extension(
        namespace="ibm",
        mechanisms={0x80019999: "CKM_IBM_UNIQUE_VENDOR"},
        inspectors={"CKM_IBM_UNIQUE_VENDOR": inspector},
    )

    assert lookup_inspector(0x80019999) is inspector


def test_extension_global_numeric_lookup_keeps_vendor_symbolic_fallback_local() -> None:
    from pkcs11_check.raw.extensions import lookup_inspector, register_extension

    ibm_inspector = lambda value: "ibm-local"
    acme_inspector = lambda value: "acme-local"

    register_extension(
        namespace="ibm",
        mechanisms={0x80018888: "CKM_SHARED_VENDOR_NAME"},
        inspectors={"CKM_SHARED_VENDOR_NAME": ibm_inspector},
    )
    register_extension(
        namespace="acme",
        mechanisms={0x80018889: "CKM_SHARED_VENDOR_NAME"},
        inspectors={"CKM_SHARED_VENDOR_NAME": acme_inspector},
    )

    assert lookup_inspector(0x80018888) is ibm_inspector


def test_extension_global_numeric_lookup_returns_none_when_vendor_id_is_ambiguous() -> None:
    from pkcs11_check.raw.extensions import lookup_inspector, register_extension

    register_extension(
        namespace="ibm",
        mechanisms={0x80016666: "CKM_IBM_AMBIG"},
        inspectors={"CKM_IBM_AMBIG": lambda value: "ibm"},
    )
    register_extension(namespace="acme", mechanisms={0x80016666: "CKM_ACME_AMBIG"})

    assert lookup_inspector(0x80016666) is None


def test_extension_clear_can_reset_one_namespace_or_all() -> None:
    from pkcs11_check.raw.extensions import clear_extensions, lookup_symbol_name, register_extension

    register_extension(namespace="ibm", mechanisms={0x80017771: "CKM_IBM_ONE"})
    register_extension(namespace="acme", mechanisms={0x80017772: "CKM_ACME_TWO"})

    clear_extensions(namespace="ibm")
    assert lookup_symbol_name("mechanisms", 0x80017771, namespace="ibm") is None
    assert lookup_symbol_name("mechanisms", 0x80017772, namespace="acme") == "CKM_ACME_TWO"

    clear_extensions()
    assert lookup_symbol_name("mechanisms", 0x80017772, namespace="acme") is None


def test_extension_clear_missing_namespace_is_noop() -> None:
    from pkcs11_check.raw import extensions
    from pkcs11_check.raw.extensions import clear_extensions

    before = set(extensions._EXTENSIONS)
    clear_extensions(namespace="ghost")
    assert set(extensions._EXTENSIONS) == before


def test_extension_register_rejects_dead_string_helper_key() -> None:
    import pytest

    from pkcs11_check.raw.extensions import register_extension

    with pytest.raises(ValueError, match="unknown vendor mechanism helper key"):
        register_extension(namespace="ibm", inspectors={"CKM_IBM_MISSING": lambda value: value})


def test_extension_register_accepts_same_call_vendor_string_helper_key() -> None:
    from pkcs11_check.raw.extensions import lookup_inspector, register_extension

    inspector = lambda value: "ok"

    register_extension(
        namespace="ibm",
        mechanisms={0x80017773: "CKM_IBM_SAME_CALL"},
        inspectors={"CKM_IBM_SAME_CALL": inspector},
    )

    assert lookup_inspector(0x80017773, namespace="ibm") is inspector


def test_extension_register_rejects_standard_name_as_vendor_helper_alias() -> None:
    import pytest

    from pkcs11_check.raw.extensions import register_extension

    with pytest.raises(ValueError, match="unknown vendor mechanism helper key"):
        register_extension(namespace="ibm", inspectors={"CKM_AES_KEY_GEN": lambda value: value})
