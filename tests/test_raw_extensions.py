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


def test_extension_global_symbol_lookup_returns_none_for_equal_value_collision() -> None:
    from pkcs11_check.raw.extensions import lookup_symbol_name, register_extension

    register_extension(namespace="ibm", mechanisms={0x80012222: "CKM_SHARED_NAME"})
    register_extension(namespace="acme", mechanisms={0x80012222: "CKM_SHARED_NAME"})

    assert lookup_symbol_name("mechanisms", 0x80012222) is None


def test_extension_registry_supports_structs_packers_and_inspectors() -> None:
    from pkcs11_check.raw.extensions import (
        clear_extensions,
        lookup_inspector,
        lookup_packer,
        lookup_struct,
        register_extension,
    )

    def packer(value: int) -> int:
        return value + 1

    def inspector(value: object) -> str:
        return repr(value)

    clear_extensions()
    register_extension(
        namespace="ibm",
        structs={"CK_IBM_KYBER_PARAMS": object()},
        packers={0x8001AA01: packer},
        inspectors={0x8001AA01: inspector},
        mechanisms={0x8001AA01: "CKM_IBM_KYBER"},
    )

    assert lookup_struct("CK_IBM_KYBER_PARAMS", namespace="ibm") is not None
    assert lookup_packer(0x8001AA01, namespace="ibm") is packer
    assert lookup_inspector(0x8001AA01, namespace="ibm") is inspector
    assert lookup_packer("CKM_IBM_KYBER", namespace="ibm") is packer
    assert lookup_inspector("CKM_IBM_KYBER", namespace="ibm") is inspector


def test_extension_global_helper_lookup_returns_none_for_equal_value_collision() -> None:
    from pkcs11_check.raw.extensions import lookup_inspector, lookup_packer, register_extension

    helper = lambda value: value

    register_extension(
        namespace="ibm",
        mechanisms={0x80012223: "CKM_SHARED_HELPER"},
        packers={"CKM_SHARED_HELPER": helper},
        inspectors={"CKM_SHARED_HELPER": helper},
    )
    register_extension(
        namespace="acme",
        mechanisms={0x80012223: "CKM_SHARED_HELPER"},
        packers={"CKM_SHARED_HELPER": helper},
        inspectors={"CKM_SHARED_HELPER": helper},
    )

    assert lookup_packer(0x80012223) is None
    assert lookup_inspector(0x80012223) is None


def test_extension_global_struct_lookup_returns_none_for_equal_value_collision() -> None:
    from pkcs11_check.raw.extensions import lookup_struct, register_extension

    shared = object()

    register_extension(namespace="ibm", structs={"CK_SHARED_STRUCT": shared})
    register_extension(namespace="acme", structs={"CK_SHARED_STRUCT": shared})

    assert lookup_struct("CK_SHARED_STRUCT") is None


def test_extension_numeric_helper_collision_requires_namespace() -> None:
    from pkcs11_check.raw.extensions import lookup_inspector, lookup_packer, register_extension

    packer_a = lambda value: value
    packer_b = lambda value: value + 1
    inspector_a = lambda value: "a"
    inspector_b = lambda value: "b"

    register_extension(
        namespace="ibm", packers={0x80010003: packer_a}, inspectors={0x80010003: inspector_a}
    )
    register_extension(
        namespace="acme", packers={0x80010003: packer_b}, inspectors={0x80010003: inspector_b}
    )

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


def test_extension_register_rejects_standard_mechanism_name_as_vendor_alias() -> None:
    import pytest

    from pkcs11_check.raw.extensions import register_extension

    with pytest.raises(
        ValueError, match="standard mechanism names are not allowed in vendor extensions"
    ):
        register_extension(
            namespace="ibm",
            mechanisms={0x80010005: "CKM_AES_KEY_GEN"},
            inspectors={"CKM_AES_KEY_GEN": lambda value: value},
        )


def test_extension_namespaced_numeric_lookup_does_not_fall_back_to_standard_name() -> None:
    import pytest

    from pkcs11_check.raw.extensions import clear_extensions, register_extension

    clear_extensions()
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
    register_extension(
        namespace="acme",
        mechanisms={0x80016666: "CKM_ACME_AMBIG"},
        inspectors={"CKM_ACME_AMBIG": lambda value: "acme"},
    )

    assert lookup_inspector(0x80016666) is None


def test_extension_global_helper_ambiguity_is_family_specific() -> None:
    from pkcs11_check.raw.extensions import lookup_inspector, lookup_packer, register_extension

    packer = lambda value: value
    inspector = lambda value: "inspector"

    register_extension(
        namespace="ibm",
        mechanisms={0x80016667: "CKM_IBM_FAMILY_SPLIT"},
        packers={"CKM_IBM_FAMILY_SPLIT": packer},
    )
    register_extension(
        namespace="acme",
        mechanisms={0x80016667: "CKM_ACME_FAMILY_SPLIT"},
        inspectors={"CKM_ACME_FAMILY_SPLIT": inspector},
    )

    assert lookup_packer(0x80016667) is packer
    assert lookup_inspector(0x80016667) is inspector


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


def test_extension_register_rejects_standard_numeric_helper_key() -> None:
    import pytest

    from pkcs11_check.raw.extensions import register_extension
    from pkcs11_check.raw.types_std import CKM_AES_KEY_GEN

    with pytest.raises(ValueError, match="standard mechanism ids are not allowed"):
        register_extension(namespace="ibm", inspectors={CKM_AES_KEY_GEN: lambda value: value})


def test_extension_register_rejects_standard_numeric_mechanism_override() -> None:
    import pytest

    from pkcs11_check.raw.extensions import register_extension
    from pkcs11_check.raw.types_std import CKM_AES_KEY_GEN

    with pytest.raises(ValueError, match="standard mechanism ids are not allowed"):
        register_extension(
            namespace="ibm",
            mechanisms={CKM_AES_KEY_GEN: "CKM_IBM_SHADOW"},
            inspectors={"CKM_IBM_SHADOW": lambda value: value},
        )


def test_extension_register_rejects_duplicate_mechanism_name_in_same_namespace() -> None:
    import pytest

    from pkcs11_check.raw.extensions import register_extension

    register_extension(namespace="ibm", mechanisms={0x80015551: "CKM_IBM_DUP"})

    with pytest.raises(ValueError, match="duplicate mechanism name in namespace"):
        register_extension(namespace="ibm", mechanisms={0x80015552: "CKM_IBM_DUP"})


def test_extension_register_rejects_mechanism_id_remap_in_same_namespace() -> None:
    import pytest

    from pkcs11_check.raw.extensions import register_extension

    register_extension(namespace="ibm", mechanisms={0x80015557: "CKM_IBM_ORIG"})

    with pytest.raises(ValueError, match="mechanism id already mapped in namespace"):
        register_extension(namespace="ibm", mechanisms={0x80015557: "CKM_IBM_REMAP"})


def test_extension_register_rejects_duplicate_mechanism_name_in_single_call() -> None:
    import pytest

    from pkcs11_check.raw.extensions import register_extension

    with pytest.raises(ValueError, match="duplicate mechanism name in namespace"):
        register_extension(
            namespace="ibm",
            mechanisms={
                0x80015553: "CKM_IBM_DUP_ONE",
                0x80015554: "CKM_IBM_DUP_ONE",
            },
        )


def test_extension_register_rejects_standard_numeric_attr_override() -> None:
    import pytest

    from pkcs11_check.raw.extensions import register_extension
    from pkcs11_check.raw.types_std import CKA_VALUE

    with pytest.raises(ValueError, match="standard symbol ids are not allowed"):
        register_extension(namespace="ibm", attrs={CKA_VALUE: "CKA_IBM_SHADOW"})


def test_extension_register_rejects_non_int_name_mapping_key() -> None:
    import pytest

    from pkcs11_check.raw.extensions import register_extension

    with pytest.raises(ValueError, match="name mapping keys must be int"):
        register_extension(namespace="ibm", mechanisms={"0x80015555": "CKM_IBM_BAD"})  # type: ignore[arg-type]


def test_extension_register_rejects_non_string_name_mapping_value() -> None:
    import pytest

    from pkcs11_check.raw.extensions import register_extension

    with pytest.raises(ValueError, match="name mapping values must be str"):
        register_extension(namespace="ibm", mechanisms={0x80015556: 123})  # type: ignore[dict-item]


def test_extension_register_rejects_bad_helper_key_type() -> None:
    import pytest

    from pkcs11_check.raw.extensions import register_extension

    with pytest.raises(ValueError, match="helper keys must be int or str"):
        register_extension(namespace="ibm", inspectors={None: lambda value: value})  # type: ignore[dict-item]


def test_extension_register_rejects_conflicting_numeric_and_symbolic_helper_values() -> None:
    import pytest

    from pkcs11_check.raw.extensions import register_extension

    helper_a = lambda value: "a"
    helper_b = lambda value: "b"

    with pytest.raises(ValueError, match="conflicting helper registration"):
        register_extension(
            namespace="ibm",
            mechanisms={0x80015558: "CKM_IBM_HELPER"},
            inspectors={0x80015558: helper_a, "CKM_IBM_HELPER": helper_b},
        )


def test_extension_register_rejects_non_mechanism_name_overwrite_with_different_value() -> None:
    import pytest

    from pkcs11_check.raw.extensions import register_extension

    register_extension(namespace="ibm", attrs={0x80025559: "CKA_IBM_ONE"})

    with pytest.raises(ValueError, match="existing namespace entry differs"):
        register_extension(namespace="ibm", attrs={0x80025559: "CKA_IBM_TWO"})


def test_extension_register_rejects_struct_overwrite_with_different_value() -> None:
    import pytest

    from pkcs11_check.raw.extensions import register_extension

    register_extension(namespace="ibm", structs={"CK_IBM_STRUCT": object()})

    with pytest.raises(ValueError, match="existing namespace entry differs"):
        register_extension(namespace="ibm", structs={"CK_IBM_STRUCT": object()})


def test_extension_register_rejects_helper_overwrite_with_different_value() -> None:
    import pytest

    from pkcs11_check.raw.extensions import register_extension

    register_extension(namespace="ibm", packers={0x8001555A: lambda value: value})

    with pytest.raises(ValueError, match="existing namespace entry differs"):
        register_extension(namespace="ibm", packers={0x8001555A: lambda value: value + 1})
