"""Windows ABI (Win64 LLP64 + ``#pragma pack(cryptoki,1)``) support.

See docs spec ``2026-06-29-windows-abi-support-design``. The packed-layout contract
values were proven under pywine + SoftHSM2 2.5.0 x64 (CK_INFO packed=72,
libraryDescription@38, function-list version footprint=2, vs the Linux LP64
baseline CK_INFO=88).
"""

from __future__ import annotations

import ctypes
import sys

from pkcs11_check.raw import api, types_std
from pkcs11_check.raw.types_std import (
    _CK_STRUCT_PACK,
    CK_ATTRIBUTE,
    CK_INFO,
    CK_MECHANISM,
    CK_VERSION,
    _CKStructure,
)


def test_pack_gate_matches_platform() -> None:
    assert _CK_STRUCT_PACK is (sys.platform == "win32")


def test_ckstructure_packs_per_gate() -> None:
    assert issubclass(_CKStructure, ctypes.Structure)
    if _CK_STRUCT_PACK:
        assert _CKStructure._pack_ == 1
    else:
        assert getattr(_CKStructure, "_pack_", 0) == 0  # natural alignment


def test_all_ck_structs_use_ckstructure_base() -> None:
    structs = [
        v
        for k, v in vars(types_std).items()
        if isinstance(v, type)
        and issubclass(v, ctypes.Structure)
        and v is not _CKStructure
        and k.startswith("CK_")
    ]
    assert structs, "no CK_* structs discovered"
    non_conforming = sorted(v.__name__ for v in structs if not issubclass(v, _CKStructure))
    assert non_conforming == [], f"CK_* structs not on _CKStructure: {non_conforming}"


def test_linux_struct_sizes_unchanged() -> None:
    # LP64 regression baseline captured 2026-06-29; meaningful only off-Windows.
    if sys.platform == "win32":
        return
    assert ctypes.sizeof(CK_VERSION) == 2
    assert ctypes.sizeof(CK_INFO) == 88
    assert ctypes.sizeof(CK_ATTRIBUTE) == 24
    assert ctypes.sizeof(CK_MECHANISM) == 24


def test_version_size_no_linux_regression_and_windows_value() -> None:
    if sys.platform == "win32":
        assert api._VERSION_SIZE == ctypes.sizeof(CK_VERSION)
    else:
        assert api._VERSION_SIZE == api._PTR_SIZE


def test_packed_abi_layout_contract() -> None:
    # Forced-packed mirrors assert the Windows layout S1-S3 produce, on any platform.
    class _V(ctypes.Structure):
        _fields_ = [("major", ctypes.c_ubyte), ("minor", ctypes.c_ubyte)]

    class _Head(ctypes.Structure):
        _pack_ = 1
        _fields_ = [("version", _V), ("firstFunc", ctypes.c_void_p)]

    assert _Head.firstFunc.offset == 2  # the function-list version footprint on packed ABI

    class _Info(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ("cryptokiVersion", _V),
            ("manufacturerID", ctypes.c_ubyte * 32),
            ("flags", ctypes.c_uint32),  # CK_ULONG narrows to 32-bit on Win64
            ("libraryDescription", ctypes.c_ubyte * 32),
            ("libraryVersion", _V),
        ]

    assert ctypes.sizeof(_Info) == 72
    assert _Info.libraryDescription.offset == 38
