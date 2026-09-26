from __future__ import annotations

import ctypes
import mmap
import sys

import pytest

import pkcs11_check.testcases._probes.honeypot as honeypot
from pkcs11_check.testcases._probes.honeypot import (
    SETUP_XFAIL_PREFIX,
    HoneypotUnavailable,
    demand_zero_buffer,
)


@pytest.fixture(autouse=True)
def reset_honeypot_cache() -> object:
    old_mapping = honeypot._honeypot_mapping
    old_size = honeypot._honeypot_size
    old_ptr = honeypot._honeypot_ptr
    old_retired = list(honeypot._retired_mappings)
    honeypot._honeypot_mapping = None
    honeypot._honeypot_size = 0
    honeypot._honeypot_ptr = None
    honeypot._retired_mappings.clear()
    try:
        yield
    finally:
        honeypot._honeypot_mapping = old_mapping
        honeypot._honeypot_size = old_size
        honeypot._honeypot_ptr = old_ptr
        honeypot._retired_mappings[:] = old_retired


def test_setup_xfail_prefix_value() -> None:
    assert SETUP_XFAIL_PREFIX == "SETUP_XFAIL:"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="POSIX mmap only")
def test_demand_zero_buffer_is_readable_far_past_a_small_buffer() -> None:
    ptr = demand_zero_buffer()
    # The whole point: indices far beyond any honestly-provisioned buffer read as 0.
    assert ptr[0] == 0
    assert ptr[(1 << 30) - 1] == 0  # Last byte of the smallest candidate mapping


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="POSIX mmap only")
def test_demand_zero_buffer_is_idempotent() -> None:
    ptr1 = demand_zero_buffer()
    ptr2 = demand_zero_buffer()
    # Both calls must return pointers to the same address (same process-lifetime mapping).
    assert ctypes.cast(ptr1, ctypes.c_void_p).value == ctypes.cast(ptr2, ctypes.c_void_p).value


def test_unavailable_carries_setup_xfail_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    import mmap as _mmap

    monkeypatch.delattr(_mmap, "MAP_ANONYMOUS", raising=False)
    with pytest.raises(HoneypotUnavailable) as exc:
        demand_zero_buffer()
    assert "POSIX" in str(exc.value)


@pytest.mark.skipif(sys.platform == "win32", reason="demand-zero honeypot needs POSIX mmap")
def test_overflow_error_falls_back_and_caches_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    real_mmap = mmap.mmap
    calls: list[int] = []

    def fake_mmap(fd: int, size: int, *, flags: int) -> mmap.mmap:
        calls.append(size)
        if len(calls) <= 2:
            raise OverflowError("candidate is too large")
        return real_mmap(fd, 4096, flags=flags)

    monkeypatch.setattr(mmap, "mmap", fake_mmap)

    ptr1 = demand_zero_buffer()
    ptr2 = demand_zero_buffer()

    assert calls == [*honeypot._HONEYPOT_SIZES[:3]]
    assert ptr1 is ptr2
    assert ptr1[0] == 0
    ptr1[0] = 0xA5
    assert ptr2[0] == 0xA5


@pytest.mark.skipif(sys.platform == "win32", reason="demand-zero honeypot needs POSIX mmap")
def test_overflow_error_exhaustion_reports_last_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def fake_mmap(fd: int, size: int, *, flags: int) -> mmap.mmap:
        calls.append(size)
        raise OverflowError("allocation exhausted")

    monkeypatch.setattr(mmap, "mmap", fake_mmap)

    with pytest.raises(HoneypotUnavailable) as exc:
        demand_zero_buffer()

    assert calls == [*honeypot._HONEYPOT_SIZES]
    assert "allocation failed" in str(exc.value)
    assert "allocation exhausted" in str(exc.value)


@pytest.mark.skipif(sys.platform == "win32", reason="demand-zero honeypot needs POSIX mmap")
def test_unrelated_mmap_error_propagates_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    error = RuntimeError("unexpected mmap failure")

    def fake_mmap(fd: int, size: int, *, flags: int) -> mmap.mmap:
        raise error

    monkeypatch.setattr(mmap, "mmap", fake_mmap)

    with pytest.raises(RuntimeError) as exc:
        demand_zero_buffer()

    assert exc.value is error


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="POSIX mmap only")
def test_demand_zero_region_carries_pointer_and_mapped_length() -> None:
    region = honeypot.demand_zero_region(0)
    assert region.mapped_length in honeypot._HONEYPOT_SIZES
    assert region.honest == 1
    assert region.ptr[0] == 0
    assert region.ptr[region.mapped_length - 1] == 0
    # demand_zero_buffer is built on the region: same mapping for no minimum.
    buf = demand_zero_buffer()
    assert ctypes.cast(buf, ctypes.c_void_p).value == ctypes.cast(region.ptr, ctypes.c_void_p).value


@pytest.mark.skipif(sys.platform == "win32", reason="demand-zero honeypot needs POSIX mmap")
def test_min_size_filters_smaller_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    real_mmap = mmap.mmap
    calls: list[int] = []

    def fake_mmap(fd: int, size: int, *, flags: int) -> mmap.mmap:
        calls.append(size)
        if size > (1 << 36):
            raise OverflowError("candidate is too large")
        return real_mmap(fd, 4096, flags=flags)

    monkeypatch.setattr(mmap, "mmap", fake_mmap)

    region = honeypot.demand_zero_region(1 << 35)

    # Only candidates satisfying the minimum are attempted.
    assert calls == [1 << 40, 1 << 38, 1 << 36]
    assert region.mapped_length == 1 << 36
    assert region.honest == 1


@pytest.mark.skipif(sys.platform == "win32", reason="demand-zero honeypot needs POSIX mmap")
def test_no_candidate_meeting_minimum_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    def fake_mmap(fd: int, size: int, *, flags: int) -> mmap.mmap:
        calls.append(size)
        raise OverflowError("allocation exhausted")

    monkeypatch.setattr(mmap, "mmap", fake_mmap)

    with pytest.raises(HoneypotUnavailable):
        honeypot.demand_zero_region(1 << 35)
    # Candidates below the minimum are never attempted.
    assert calls == [1 << 40, 1 << 38, 1 << 36]

    with pytest.raises(HoneypotUnavailable) as exc:
        demand_zero_buffer(min_size=(1 << 40) + 1)
    assert "minimum" in str(exc.value).lower()


@pytest.mark.skipif(sys.platform == "win32", reason="demand-zero honeypot needs POSIX mmap")
def test_smaller_cached_mapping_is_never_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(honeypot, "_HONEYPOT_SIZES", (4096,))
    small = honeypot.demand_zero_region(0)
    assert small.mapped_length == 4096
    small.ptr[0] = 0xA5

    monkeypatch.setattr(honeypot, "_HONEYPOT_SIZES", (8192,))
    big = honeypot.demand_zero_region(5000)

    assert big.mapped_length == 8192
    assert (
        ctypes.cast(big.ptr, ctypes.c_void_p).value != ctypes.cast(small.ptr, ctypes.c_void_p).value
    )
    # The superseded mapping stays alive: outstanding pointers keep working.
    assert small.ptr[0] == 0xA5

    # A later smaller request is satisfied by the larger cached mapping.
    again = honeypot.demand_zero_region(100)
    assert (
        ctypes.cast(again.ptr, ctypes.c_void_p).value == ctypes.cast(big.ptr, ctypes.c_void_p).value
    )


def test_hostile_unbacked_region_is_marked_not_honest() -> None:
    buf = (ctypes.c_ubyte * 8)()
    ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
    region = honeypot.hostile_unbacked_region(ptr)
    assert region.honest == 0
    assert region.mapped_length == 0
