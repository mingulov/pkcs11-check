"""Windows ABI (Win64 LLP64 + ``#pragma pack(cryptoki,1)``) support.

See docs spec ``2026-06-29-windows-abi-support-design``. The packed-layout contract
values were proven under pywine + SoftHSM2 2.5.0 x64 (CK_INFO packed=72,
libraryDescription@38, function-list version footprint=2, vs the Linux LP64
baseline CK_INFO=88).

The G1 tests below additionally build *generative* LLP64 mirrors of every
generated ``CK_*`` struct (platform-assumption design 2026-10-25, section
5.2): ``CK_ULONG`` fields narrow to ``c_uint32``, pointers stay host pointers
(8 bytes on every CI host = Win64 pointer width), packing is forced to 1.
The mirrors are Python-only and generator-derived -- cross-checks for a
future native-header oracle, never ABI proof on their own. A 4-byte-pointer
(ILP32) host cannot express the Win64 pointer width; the golden pins fail
loud there instead of silently asserting ILP32 layouts.
"""

from __future__ import annotations

import ctypes
import sys
from typing import Any

from pkcs11_check.raw import api, types_std
from pkcs11_check.raw.types_std import (
    _CK_STRUCT_PACK,
    CK_ATTRIBUTE,
    CK_FUNCTION_LIST,
    CK_INFO,
    CK_MECHANISM,
    CK_VERSION,
    _CKStructure,
)
from pkcs11_check.testcases._probes import _ckr_ctypes


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


# --- G1: generative LLP64 mirrors -------------------------------------------
#
# Every generated CK_* struct gets a mirror with CK_ULONG narrowed to 32 bits
# and _pack_ = 1. Only the hand-walked / provider-sent subset gets numeric
# goldens; the rest assert buildability + never-wider-than-host, so nobody
# pins ~100 values they cannot independently verify. Golden numbers below
# were re-derived on an LP64 Linux host (Python 3.13, 8-byte pointer) with
# exactly this construction; LP64 host baselines are 88 / 24 / 24 / 552.

_MIRRORS: dict[type[ctypes.Structure], type[ctypes.Structure]] = {}


def _mirror_type(ftype: Any) -> Any:
    if ftype is types_std.CK_ULONG:  # every CK_ULONG typedef aliases c_ulong
        return ctypes.c_uint32
    if issubclass(ftype, ctypes.Array):
        return _mirror_type(ftype._type_) * ftype._length_
    if issubclass(ftype, ctypes.Structure):
        return _llp64_mirror(ftype)
    return ftype  # pointers, function pointers, fixed-width scalars: unchanged


def _llp64_mirror(cls: type[ctypes.Structure]) -> type[ctypes.Structure]:
    if cls in _MIRRORS:
        return _MIRRORS[cls]
    fields: list[tuple[str, Any] | tuple[str, Any, Any]] = []
    for field in cls._fields_:
        if len(field) == 3:  # bitfield: keep the width, narrow the base type
            fields.append((field[0], _mirror_type(field[1]), field[2]))
        else:
            fields.append((field[0], _mirror_type(field[1])))
    namespace: dict[str, object] = {"_pack_": 1, "_fields_": fields}
    if sys.version_info >= (3, 14):  # _layout_ exists from 3.14; "ms" is the Win64 layout
        namespace["_layout_"] = "ms"
    mirror: type[ctypes.Structure] = type(f"LLP64_{cls.__name__}", (ctypes.Structure,), namespace)
    _MIRRORS[cls] = mirror
    return mirror


def _ck_structs() -> list[tuple[str, type[ctypes.Structure]]]:
    return sorted(
        (k, v)
        for k, v in vars(types_std).items()
        if isinstance(v, type)
        and issubclass(v, ctypes.Structure)
        and k.startswith("CK_")
        and v is not _CKStructure
    )


def test_llp64_mirrors_buildable_and_never_wider_than_host() -> None:
    structs = _ck_structs()
    assert len(structs) >= 100, f"CK struct discovery shrank: {len(structs)}"
    for name, cls in structs:
        mirror = _llp64_mirror(cls)
        assert [f[0] for f in mirror._fields_] == [f[0] for f in cls._fields_], name
        assert ctypes.sizeof(mirror) <= ctypes.sizeof(cls), (
            f"{name}: LLP64 mirror {ctypes.sizeof(mirror)} wider than host {ctypes.sizeof(cls)}"
        )
        # The narrowing must actually happen (an identity mirror passes the
        # size check above vacuously): direct CK_ULONG fields become 4 bytes.
        for field in cls._fields_:
            if field[1] is types_std.CK_ULONG:
                assert getattr(mirror, field[0]).size == 4, f"{name}.{field[0]} not narrowed"


def test_llp64_mirror_golden_layouts() -> None:
    info = _llp64_mirror(CK_INFO)
    assert ctypes.sizeof(info) == 72
    assert info.libraryDescription.offset == 38

    attribute = _llp64_mirror(CK_ATTRIBUTE)
    assert ctypes.sizeof(attribute) == 16
    assert attribute.ulValueLen.offset == 12

    mechanism = _llp64_mirror(CK_MECHANISM)
    assert ctypes.sizeof(mechanism) == 16
    assert mechanism.ulParameterLen.offset == 12

    # Hand-walked by raw.api and the ckr probes: first function pointer
    # directly after the 2-byte version, no pointer-boundary padding.
    flist = _llp64_mirror(CK_FUNCTION_LIST)
    assert ctypes.sizeof(flist) == 546
    assert flist.C_Initialize.offset == 2


def test_llp64_mirror_function_list_head_matches_hand_walk() -> None:
    """The packed golden head (2) is what the hand-walk consumers must use.

    Regression shape of design section 6 row 4: the ckr walk once hardcoded
    the header to ``sizeof(c_void_p)`` (8 -- the LP64-natural mirror offset),
    which reads every function pointer from the wrong slot on the packed
    ABI. The walk must take its header from the packing-aware api helper
    and accept the packed golden as its slot-0 offset.
    """
    mirror = _llp64_mirror(CK_FUNCTION_LIST)
    head = mirror.C_Initialize.offset
    assert head == ctypes.sizeof(CK_VERSION) == 2
    assert head != CK_FUNCTION_LIST.C_Initialize.offset or _CK_STRUCT_PACK
    assert _ckr_ctypes._slot_offset(0, header_size=head, ptr_size=8) == head
    assert _ckr_ctypes._HEADER_SIZE == api.function_list_header_size()
