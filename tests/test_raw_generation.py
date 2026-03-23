from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path


def test_vendored_header_exists() -> None:
    assert Path("third_party/pkcs11-headers/3.2/pkcs11.h").is_file()


def test_vendored_header_local_dependencies_exist() -> None:
    header = Path("third_party/pkcs11-headers/3.2/pkcs11.h")
    includes = re.findall(r'^#include "([^"]+)"$', header.read_text(), flags=re.MULTILINE)
    for include in includes:
        assert (header.parent / include).is_file()


def test_generated_modules_exist() -> None:
    assert importlib.util.find_spec("pkcs11_check.raw.types_std") is not None
    assert importlib.util.find_spec("pkcs11_check.raw.metadata_std") is not None


def test_generator_writes_explicit_outputs(tmp_path: Path) -> None:
    from scripts.generate_raw_standard import generate_raw_standard

    header = tmp_path / "pkcs11.h"
    header.write_text("#include \"pkcs11t.h\"\n#include \"pkcs11f.h\"\n")
    (tmp_path / "pkcs11t.h").write_text("typedef int dummy_t;\n")
    (tmp_path / "pkcs11f.h").write_text("typedef int dummy_f;\n")

    out_types = tmp_path / "types_std.py"
    out_metadata = tmp_path / "metadata_std.py"

    generate_raw_standard(header=header, out_types=out_types, out_metadata=out_metadata)

    assert out_types.read_text() == (
        '"""Generated PKCS#11 standard types/constants."""\n'
        "from __future__ import annotations\n\n"
        "STANDARD_GENERATED = True\n"
    )
    assert out_metadata.read_text() == (
        '"""Generated PKCS#11 standard metadata."""\n'
        "from __future__ import annotations\n\n"
        'STANDARD_COUNTS = {"functions": 0, "attrs": 0, "mechanisms": 0}\n'
    )


def test_generator_script_works_outside_repo_root(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "generate_raw_standard.py"
    workdir = tmp_path / "outside"
    workdir.mkdir()

    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=workdir,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert (repo_root / "src/pkcs11_check/raw/types_std.py").is_file()
    assert (repo_root / "src/pkcs11_check/raw/metadata_std.py").is_file()


def test_generated_standard_symbols_cover_representative_values() -> None:
    from pkcs11_check.raw import metadata_std, types_std

    assert metadata_std.STANDARD_COUNTS["functions"] == 104
    assert metadata_std.STANDARD_COUNTS["attrs"] >= 160
    assert metadata_std.STANDARD_COUNTS["mechanisms"] >= 480
    assert hasattr(types_std, "CKA_CLASS")
    assert hasattr(types_std, "CKM_AES_GCM")
    assert hasattr(types_std, "CKK_AES")
    assert hasattr(types_std, "CK_GCM_PARAMS")
