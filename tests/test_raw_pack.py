from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path


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
    assert attr.pointer_arg.native_length == 4
    assert len(attr.storage) == 4
    assert attr.length_arg.explicit is True
    assert attr.length_arg.value == 2


def test_template_retains_packed_attributes_for_inspection() -> None:
    from pkcs11_check.raw.pack import attr_bool, attr_ulong, template

    value = template(attr_bool(0x00000104, True), attr_ulong(0x00000161, 32))

    assert len(value.attributes) == 2
    assert value.attributes[0].pointer_arg.kind == "scalar"


def test_pack_mech_bytes_native_length_matches_payload_length() -> None:
    from pkcs11_check.raw.pack import mech_bytes

    value = mech_bytes(0x80010099, b"abc")
    assert value.pointer_arg.native_length == 3
    assert len(value.storage) == 3


def test_wheel_includes_vendored_standard_header_and_generated_raw_modules(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    dist_dir = tmp_path / "dist"

    result = subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(dist_dir)],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr

    wheel_path = next(dist_dir.glob("*.whl"))
    with zipfile.ZipFile(wheel_path) as wheel:
        names = set(wheel.namelist())

    assert "pkcs11_check/raw/types_std.py" in names
    assert "pkcs11_check/raw/metadata_std.py" in names
    assert "pkcs11_check/_vendor/pkcs11-headers/3.2/pkcs11.h" in names
