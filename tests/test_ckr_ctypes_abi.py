"""ABI-correctness guards for the raw ckr function-list bootstrap (`_probes/_ckr_ctypes`).

Regression guards for the packed-Windows-ABI class of bug: the ckr probes resolve
``C_*`` function pointers by walking a CK_FUNCTION_LIST by hand, and that walk must agree
with the canonical ``raw.api`` walk on BOTH the natural (Linux) and packed (Windows) ABIs.
Two historical defects motivated these:

* the header offset was hardcoded to ``sizeof(c_void_p)`` (8), correct on Linux only by
  coincidence (CK_VERSION pads to the pointer boundary) but wrong under ``_pack_=1`` where
  the first function pointer sits at ``sizeof(CK_VERSION)`` (2);
* the function-index table was a hand copy that had already drifted from the generated
  ``metadata_std.FUNCTION_INDICES`` (``C_GenerateRandom`` mapped to 48 == ``C_VerifyInit``).
"""

from __future__ import annotations

import ctypes

from pkcs11_check.raw import api, metadata_std
from pkcs11_check.raw.types_std import CK_VERSION
from pkcs11_check.testcases._probes import _ckr_ctypes


def _make_fake_function_list(
    num_slots: int, header_size: int, ptr_size: int
) -> tuple[object, ctypes.c_void_p, list[int]]:
    """Build an in-memory CK_FUNCTION_LIST-shaped buffer with sentinel slot addresses."""
    buf = (ctypes.c_ubyte * (header_size + num_slots * ptr_size))()
    sentinels: list[int] = []
    for i in range(num_slots):
        addr = 0x100000 + (i + 1) * 0x1000
        sentinels.append(addr)
        ctypes.c_void_p.from_buffer(buf, header_size + i * ptr_size).value = addr
    flist = ctypes.cast(buf, ctypes.c_void_p)
    return buf, flist, sentinels


def test_func_indices_match_generated_table() -> None:
    """Every ckr function index must equal the generated single source of truth (A2)."""
    for name, idx in _ckr_ctypes.FUNC_INDICES.items():
        assert idx == metadata_std.FUNCTION_INDICES[name], (
            f"{name} index {idx} drifted from generated {metadata_std.FUNCTION_INDICES[name]}"
        )


def test_c_generate_random_resolves_to_generated_slot() -> None:
    """The previously-drifted entry must now be the real slot, not C_VerifyInit's (A2)."""
    assert _ckr_ctypes.FUNC_INDICES["C_GenerateRandom"] == 64
    assert (
        _ckr_ctypes.FUNC_INDICES["C_GenerateRandom"]
        != metadata_std.FUNCTION_INDICES["C_VerifyInit"]
    )


def test_slot_offset_is_header_parameterized() -> None:
    """Slot arithmetic takes the header size as input, so the packed ABI (header=2) works (A1)."""
    # packed layout: version (2 bytes) then pointers, no padding
    assert _ckr_ctypes._slot_offset(0, header_size=2, ptr_size=8) == 2
    assert _ckr_ctypes._slot_offset(5, header_size=2, ptr_size=8) == 2 + 5 * 8
    # natural layout: version padded to the pointer boundary
    assert _ckr_ctypes._slot_offset(0, header_size=8, ptr_size=8) == 8
    assert _ckr_ctypes._slot_offset(5, header_size=8, ptr_size=8) == 8 + 5 * 8


def test_header_size_comes_from_api_not_pointer_size() -> None:
    """The ckr walk must source its header size from the packing-aware raw.api helper (A1)."""
    assert _ckr_ctypes._HEADER_SIZE == api.function_list_header_size()


def test_packed_function_list_head_first_func_at_version_size() -> None:
    """Lock the ctypes behavior the fix relies on: under _pack_=1, firstFunc is at CK_VERSION."""

    class _PackedHead(ctypes.Structure):
        _pack_ = 1
        _fields_ = [("version", CK_VERSION), ("firstFunc", ctypes.c_void_p)]

    assert _PackedHead.firstFunc.offset == ctypes.sizeof(CK_VERSION)
    assert _PackedHead.firstFunc.offset != ctypes.sizeof(ctypes.c_void_p)


def test_make_caller_walks_natural_layout_correctly() -> None:
    """End-to-end: get_func reads the correct slot for the platform's real header size."""
    header = api.function_list_header_size()
    ptr = ctypes.sizeof(ctypes.c_void_p)
    _buf, flist, sentinels = _make_fake_function_list(66, header, ptr)
    _call_func, get_func = _ckr_ctypes.make_caller(flist)
    for name in ("C_Initialize", "C_GetInfo", "C_GenerateRandom"):
        idx = metadata_std.FUNCTION_INDICES[name]
        assert get_func(idx) == sentinels[idx], name


def test_make_caller_builds_signature_from_actual_args() -> None:
    """call_func deliberately derives the CFUNCTYPE from the caller's own ctypes objects.

    This is intentional for a fault-injection probe (it must pass NULL / malformed args the
    RawPKCS11 wrapper would reject), so it must NOT be "fixed" to static signatures. A bare
    Python arg already fails loud at CFUNCTYPE construction; assert that contract holds.
    """
    _buf, flist, _sentinels = _make_fake_function_list(66, api.function_list_header_size(), 8)
    call_func, _get_func = _ckr_ctypes.make_caller(flist)
    try:
        call_func("C_Initialize", 0)  # bare int, not a ctypes object
    except TypeError:
        pass  # audit-ok: asserting the documented fail-loud contract, not swallowing a finding
    else:  # pragma: no cover - construction must reject a non-ctypes arg
        raise AssertionError("expected a TypeError for a non-ctypes argument")
