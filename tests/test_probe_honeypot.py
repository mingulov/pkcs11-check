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
    old_ptr = honeypot._honeypot_ptr
    honeypot._honeypot_mapping = None
    honeypot._honeypot_ptr = None
    try:
        yield
    finally:
        honeypot._honeypot_mapping = old_mapping
        honeypot._honeypot_ptr = old_ptr


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
