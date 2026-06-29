"""S5: triage of >32-bit literal values for the Windows 32-bit-CK_ULONG ABI.

Two categories (see docs spec 2026-06-29-windows-abi-support-design):
  (a) "max CK_ULONG" probes -> width-relative (run everywhere at the platform max).
  (b) 64-bit gap values in (2^32, 2^64) -> the module-side 64->32 truncation class is
      only reachable from a 64-bit caller; the value is unrepresentable in a 32-bit
      CK_ULONG, so those whole modules skip (never silently truncate -> would hide findings).
"""

from __future__ import annotations

import ctypes
import importlib

from pkcs11_check.testcases.security._boundary_values import (
    CK_ULONG_IS_64BIT,
    requires_64bit_ck_ulong,
)

# (b) modules whose every probe needs a 64-bit CK_ULONG caller.
GAP_VALUE_MODULES = [
    "pkcs11_check.testcases.security.test_digest_length_truncation",
    "pkcs11_check.testcases.security.test_random_length_truncation",
    "pkcs11_check.testcases.security.test_output_length_truncation",
    "pkcs11_check.testcases.security.test_field_size_boundary",
    "pkcs11_check.testcases.security.test_recover_length_boundary",
]


def test_ck_ulong_is_64bit_flag_matches_platform() -> None:
    assert CK_ULONG_IS_64BIT == (ctypes.sizeof(ctypes.c_ulong) >= 8)


def test_requires_64bit_is_skipif_keyed_on_width() -> None:
    assert requires_64bit_ck_ulong.name == "skipif"
    assert requires_64bit_ck_ulong.args[0] == (not CK_ULONG_IS_64BIT)


def test_gap_value_modules_skip_on_32bit_ulong() -> None:
    for modname in GAP_VALUE_MODULES:
        mod = importlib.import_module(modname)
        marks = list(getattr(mod, "pytestmark", []))
        assert requires_64bit_ck_ulong in marks, f"{modname} must gate on 64-bit CK_ULONG"


def test_max_ulong_probe_constants_are_width_relative() -> None:
    from pkcs11_check.testcases.security.test_aes_keywrap_pad_overflow import _OVERSIZED_DATALEN
    from pkcs11_check.testcases.security.test_api_boundary import _CK_ULONG_MAX

    expected = ctypes.c_ulong(-1).value  # 2^64-1 on LP64, 2^32-1 on Win64 LLP64
    assert _OVERSIZED_DATALEN == expected
    assert _CK_ULONG_MAX == expected
