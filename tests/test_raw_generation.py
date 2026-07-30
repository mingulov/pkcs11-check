from __future__ import annotations

import ctypes
import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


def _field_map(fields: Any) -> dict[str, Any]:
    return {field[0]: field[1] for field in fields}


def test_vendored_header_exists() -> None:
    assert Path("third_party/pkcs11-headers/3.2/pkcs11.h").is_file()


def test_vendored_header_local_dependencies_exist() -> None:
    header = Path("third_party/pkcs11-headers/3.2/pkcs11.h")
    includes = re.findall(
        r'^#include "([^"]+)"$', header.read_text(encoding="utf-8"), flags=re.MULTILINE
    )
    for include in includes:
        assert (header.parent / include).is_file()


def test_vendored_header_x942_mqv_pointer_field_names_match_oasis() -> None:
    header = Path("third_party/pkcs11-headers/3.2/pkcs11.h")
    text = header.read_text(encoding="utf-8")
    match = re.search(
        r"struct CK_X9_42_MQV_DERIVE_PARAMS \{(?P<body>.*?)\};",
        text,
        flags=re.DOTALL,
    )
    assert match is not None
    body = match.group("body")

    assert "pOtherInfo" in body
    assert "pPublicData" in body
    assert "pPublicData2" in body
    assert "CK_BYTE * OtherInfo;" not in body
    assert "CK_BYTE * PublicData;" not in body
    assert "CK_BYTE * PublicData2;" not in body


def test_generated_modules_exist() -> None:
    assert importlib.util.find_spec("pkcs11_check.raw.types_std") is not None
    assert importlib.util.find_spec("pkcs11_check.raw.metadata_std") is not None


def test_generator_writes_explicit_outputs(tmp_path: Path) -> None:
    from scripts.generate_raw_standard import generate_raw_standard

    header = tmp_path / "pkcs11.h"
    header.write_text('#include "pkcs11t.h"\n#include "pkcs11f.h"\n', encoding="utf-8")
    (tmp_path / "pkcs11t.h").write_text("typedef int dummy_t;\n", encoding="utf-8")
    (tmp_path / "pkcs11f.h").write_text("typedef int dummy_f;\n", encoding="utf-8")

    out_types = tmp_path / "types_std.py"
    out_metadata = tmp_path / "metadata_std.py"

    generate_raw_standard(header=header, out_types=out_types, out_metadata=out_metadata)

    # Generator runs ruff format, so check content not exact formatting
    types_content = out_types.read_text(encoding="utf-8")
    assert "STANDARD_GENERATED = True" in types_content
    assert "from __future__ import annotations" in types_content

    metadata_content = out_metadata.read_text(encoding="utf-8")
    assert '"functions": 0' in metadata_content
    assert "from __future__ import annotations" in metadata_content


def test_generator_script_works_outside_repo_root(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "generate_raw_standard.py"
    workdir = tmp_path / "outside"
    workdir.mkdir()

    result = subprocess.run(
        [sys.executable, str(script)], cwd=workdir, capture_output=True, text=True, encoding="utf-8"
    )

    assert result.returncode == 0, result.stderr
    assert (repo_root / "src/pkcs11_check/raw/types_std.py").is_file()
    assert (repo_root / "src/pkcs11_check/raw/metadata_std.py").is_file()


def test_generated_standard_symbols_cover_representative_values() -> None:
    from pkcs11_check.raw import metadata_std, types_std

    assert metadata_std.STANDARD_COUNTS["functions"] == 110
    assert metadata_std.STANDARD_COUNTS["attrs"] >= 160
    assert metadata_std.STANDARD_COUNTS["mechanisms"] >= 480
    assert hasattr(types_std, "CKA_CLASS")
    assert hasattr(types_std, "CKM_AES_GCM")
    assert hasattr(types_std, "CKK_AES")
    assert hasattr(types_std, "CK_GCM_PARAMS")
    assert hasattr(types_std, "CK_KMAC_PARAMS")


def test_generated_standard_types_preserve_struct_pointer_aliases() -> None:
    from pkcs11_check.raw import types_std

    assert hasattr(types_std, "CK_NOTIFY")
    assert types_std.CK_INFO_PTR._type_ is types_std.CK_INFO
    assert types_std.CK_MECHANISM_PTR._type_ is types_std.CK_MECHANISM
    assert types_std.CK_GCM_PARAMS_PTR._type_ is types_std.CK_GCM_PARAMS
    assert (
        types_std.CK_TLS12_MASTER_KEY_DERIVE_PARAMS_PTR._type_
        is types_std.CK_TLS12_MASTER_KEY_DERIVE_PARAMS
    )


def test_generated_standard_types_preserve_nested_struct_fields() -> None:
    from pkcs11_check.raw import types_std

    assert _field_map(types_std.CK_INFO._fields_)["cryptokiVersion"] is types_std.CK_VERSION
    assert _field_map(types_std.CK_SLOT_INFO._fields_)["hardwareVersion"] is types_std.CK_VERSION


def test_generated_standard_types_preserve_kmac_overlay() -> None:
    from pkcs11_check.raw import types_std

    fields = _field_map(types_std.CK_KMAC_PARAMS._fields_)

    assert fields["hKey"] is types_std.CK_OBJECT_HANDLE
    assert fields["ulMacLength"] is types_std.CK_ULONG
    assert fields["pCustomizationString"] is types_std.CK_BYTE_PTR
    assert fields["ulCustomizationStringLen"] is types_std.CK_ULONG


def test_generated_standard_callback_typedefs_are_usable_field_types() -> None:
    from pkcs11_check.raw import types_std

    fields = _field_map(types_std.CK_C_INITIALIZE_ARGS._fields_)

    assert fields["CreateMutex"] is types_std.CK_CREATEMUTEX
    assert fields["DestroyMutex"] is types_std.CK_DESTROYMUTEX
    assert fields["LockMutex"] is types_std.CK_LOCKMUTEX
    assert fields["UnlockMutex"] is types_std.CK_UNLOCKMUTEX


def test_generated_standard_function_list_structs_are_real_structures() -> None:
    from pkcs11_check.raw import types_std

    assert hasattr(types_std, "CK_FUNCTION_LIST")
    assert issubclass(types_std.CK_FUNCTION_LIST, ctypes.Structure)
    assert issubclass(types_std.CK_FUNCTION_LIST_3_0, ctypes.Structure)
    assert issubclass(types_std.CK_FUNCTION_LIST_3_2, ctypes.Structure)
    fields_240 = _field_map(types_std.CK_FUNCTION_LIST._fields_)
    fields_30 = _field_map(types_std.CK_FUNCTION_LIST_3_0._fields_)
    fields_32 = _field_map(types_std.CK_FUNCTION_LIST_3_2._fields_)

    assert fields_240["version"] is types_std.CK_VERSION
    assert fields_240["C_Initialize"] is types_std.CK_C_Initialize
    assert "C_GetInterfaceList" not in fields_240

    assert fields_30["version"] is types_std.CK_VERSION
    assert fields_30["C_GetInterfaceList"] is types_std.CK_C_GetInterfaceList
    assert "C_EncapsulateKey" not in fields_30

    assert fields_32["version"] is types_std.CK_VERSION
    assert fields_32["C_EncapsulateKey"] is types_std.CK_C_EncapsulateKey


def test_attr_value_types_covers_common_attrs() -> None:
    """ATTR_VALUE_TYPES covers at least the common attributes."""
    from pkcs11_check.raw.attr_metadata import ATTR_VALUE_TYPES
    from pkcs11_check.raw.metadata_std import ATTR_NAMES

    # Every entry in ATTR_VALUE_TYPES must be a valid CKA constant
    for attr_id in ATTR_VALUE_TYPES:
        assert attr_id in ATTR_NAMES, f"Unknown attr {attr_id:#x} in ATTR_VALUE_TYPES"

    # Core attrs must be present
    from pkcs11_check.raw.types_std import (
        CKA_CLASS,
        CKA_DECRYPT,
        CKA_ENCRYPT,
        CKA_KEY_TYPE,
        CKA_LABEL,
        CKA_MODULUS,
        CKA_TOKEN,
        CKA_VALUE,
        CKA_VALUE_LEN,
    )

    for attr in (
        CKA_CLASS,
        CKA_TOKEN,
        CKA_LABEL,
        CKA_KEY_TYPE,
        CKA_VALUE,
        CKA_ENCRYPT,
        CKA_DECRYPT,
        CKA_MODULUS,
        CKA_VALUE_LEN,
    ):
        assert int(attr) in ATTR_VALUE_TYPES, f"{attr} missing from ATTR_VALUE_TYPES"


def test_attr_value_types_valid_type_strings() -> None:
    """All type values are recognized strings."""
    from pkcs11_check.raw.attr_metadata import ATTR_VALUE_TYPES

    valid = {"bool", "ulong", "bytes", "str", "date", "ulong_array", "template"}
    for attr_id, vtype in ATTR_VALUE_TYPES.items():
        assert vtype in valid, f"Attr {attr_id:#x} has unknown type {vtype!r}"


def test_attr_value_types_matches_python_pkcs11() -> None:
    """ATTR_VALUE_TYPES agrees with python-pkcs11 on value type categories."""
    import pytest

    from pkcs11_check.raw.attr_metadata import ATTR_VALUE_TYPES

    try:
        from pkcs11.attributes import (  # type: ignore[import-not-found]
            ATTRIBUTE_TYPES,
            handle_biginteger,
            handle_bool,
            handle_bytes,
            handle_date,
            handle_str,
            handle_ulong,
        )
    except ImportError:
        pytest.skip("python-pkcs11 not available")

    # Map python-pkcs11 handler -> our type string
    handler_map = {
        id(handle_bool): "bool",
        id(handle_ulong): "ulong",
        id(handle_str): "str",
        id(handle_bytes): "bytes",
        id(handle_biginteger): "bytes",  # big integer stored as bytes
        id(handle_date): "date",
    }

    mismatches = []
    for attr, handler in ATTRIBUTE_TYPES.items():
        attr_id = int(attr)
        if attr_id not in ATTR_VALUE_TYPES:
            continue  # We may not cover all python-pkcs11 attrs
        expected = handler_map.get(id(handler))
        if expected is None:
            continue  # Enum handlers, array handlers -- skip
        actual = ATTR_VALUE_TYPES[attr_id]
        if actual != expected:
            mismatches.append(f"CKA {attr_id:#x}: ours={actual}, fork={expected}")

    assert not mismatches, "Type mismatches:\n" + "\n".join(mismatches)
