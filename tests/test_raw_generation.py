from __future__ import annotations

import importlib.util
import re
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
